package postgres

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
)

func (r *Repository) GetProfileActivationCode(ctx context.Context, userId uuid.UUID) (string, error) {
	var code string

	query := fmt.Sprintf(`
		SELECT activation_code
		FROM %s
		WHERE user_id=$1
	`, activationCodesTable)

	if err := r.db.GetContext(ctx, &code, query, userId); err != nil {
		log.AutoErrorf("activation code for user %s not found: %s", userId, err)
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

	res, queryErr := r.db.ExecContext(ctx, activateProfileQuery, userId, code)
	if rows, err := res.RowsAffected(); queryErr != nil || err != nil || rows == 0 {
		log.AutoInfof("invalid activation code %s for user %s: %s", code, userId, err)
		return fail.GrpcInvalidActivationCode
	}

	return nil
}
