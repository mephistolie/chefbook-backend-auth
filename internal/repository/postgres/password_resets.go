package postgres

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (r *Repository) CreatePasswordResetRequest(ctx context.Context, userId uuid.UUID, expiration time.Time) (uuid.UUID, error) {
	resetCode := uuid.UUID{}

	r.removeOutdatedPasswordResetRequests(ctx, userId)

	getExistingResetCodeQuery := fmt.Sprintf(`
		SELECT reset_code
		FROM %s
		WHERE user_id=$1 AND used=false
	`, passwordResetsTable)
	if err := r.db.GetContext(ctx, &resetCode, getExistingResetCodeQuery, userId); err == nil {
		log.AutoInfof("found existing password reset code for user %s", userId)
		return resetCode, nil
	}

	resetCode = uuid.New()
	createResetCodeQuery := fmt.Sprintf(`
		INSERT INTO %s (user_id, reset_code, expires_at)
		VALUES ($1, $2, $3)
	`, passwordResetsTable)
	if _, err := r.db.ExecContext(ctx, createResetCodeQuery, userId, resetCode.String(), expiration); err != nil {
		log.AutoErrorf("error while creating reset code for user %s: %s", userId, err)
		return uuid.UUID{}, fail.GrpcUnknown
	}

	return resetCode, nil
}

func (r *Repository) removeOutdatedPasswordResetRequests(ctx context.Context, userId uuid.UUID) {
	query := fmt.Sprintf(`
		DELETE FROM %[1]v
		WHERE user_id=$1 AND used=false AND expires_at<=$2
	`, passwordResetsTable)

	if _, err := r.db.ExecContext(ctx, query, userId, time.Now()); err != nil {
		log.AutoErrorf("error while delete outdated reset codes for user %s: %s", userId, err)
	}
}

func (r *Repository) ResetPassword(ctx context.Context, userId uuid.UUID, resetCode string, passwordHash string) error {

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		log.AutoError("unable to begin transaction: ", err)
		return fail.GrpcUnknown
	}

	userResetCodeQuery := fmt.Sprintf(`
		UPDATE %s
		SET used=true
		WHERE user_id=$1 AND reset_code=$2 AND used=false AND expires_at>$3
	`, passwordResetsTable)

	res, err := tx.ExecContext(ctx, userResetCodeQuery, userId, resetCode, time.Now())
	if err != nil {
		log.AutoErrorf("invalid reset code %s for user %s: %s", resetCode, userId, err)
		return errorWithTransactionRollback(tx, authFail.GrpcInvalidResetPasswordCode)
	}
	if rows, err := res.RowsAffected(); err != nil || rows == 0 {
		log.AutoInfof("invalid or expired reset code %s for user %s: %s", resetCode, userId, err)
		return errorWithTransactionRollback(tx, authFail.GrpcInvalidResetPasswordCode)
	}

	changePasswordQuery := fmt.Sprintf(`
		UPDATE %s
		SET password=$1
		WHERE user_id=$2
	`, usersTable)

	if _, err := tx.ExecContext(ctx, changePasswordQuery, passwordHash, userId); err != nil {
		log.AutoErrorf("error while updating password for user %s: %s", userId, err)
		return errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	return commitTransaction(tx)
}

func (r *Repository) SetPassword(ctx context.Context, userId uuid.UUID, passwordHash string) error {
	id := ""

	changePasswordQuery := fmt.Sprintf(`
		UPDATE %s
		SET password=$1
		WHERE user_id=$2
		RETURNING user_id
	`, usersTable)

	row := r.db.QueryRowContext(ctx, changePasswordQuery, passwordHash, userId)
	if err := row.Scan(&id); err != nil || id == "" {
		log.AutoErrorf("error while updating password for user %s: %s", userId, err)
		return fail.GrpcUnknown
	}

	return nil
}
