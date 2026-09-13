package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
)

func (r *Repository) GetProfileActivationCode(ctx context.Context, userId uuid.UUID) (string, error) {
	var code string

	query := fmt.Sprintf(`
		SELECT activation_code
		FROM %s
		WHERE user_id=$1
	`, activationCodesTable)

	if err := r.db.GetContext(ctx, &code, query, userId); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "GetProfileActivationCode",
			UserID:    userId.String(),
			Entity:    "activation_code",
		}, err)
		return "", fail.GrpcActivationLinkNotFound
	}

	return code, nil
}

func (r *Repository) ActivateProfile(ctx context.Context, userId uuid.UUID, code string) error {

	activateProfileQuery := fmt.Sprintf(`
		UPDATE %s
		SET activated=true
		WHERE user_id=
		(
			SELECT user_id
			FROM %s
			WHERE user_id=$1 AND activation_code=$2
		)
	`, usersTable, activationCodesTable)

	res, err := r.db.ExecContext(ctx, activateProfileQuery, userId, code)
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "ActivateProfile",
			UserID:    userId.String(),
			Entity:    "activation_code",
		}, err)
		return fail.GrpcInvalidActivationCode
	}
	rows, err := res.RowsAffected()
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "ReadActivatedProfileCount",
			UserID:    userId.String(),
			Entity:    "activation_code",
		}, err)
		return fail.GrpcInvalidActivationCode
	}
	if rows == 0 {
		authlog.Default.ActivationCodeRejected(ctx, userId.String())
		return fail.GrpcInvalidActivationCode
	}

	return nil
}
