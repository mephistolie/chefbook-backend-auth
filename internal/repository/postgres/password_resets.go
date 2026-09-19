package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
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
		authlog.Default.PasswordResetReused(ctx, userId.String())
		return resetCode, nil
	}

	resetCode = uuid.New()
	createResetCodeQuery := fmt.Sprintf(`
		INSERT INTO %s (user_id, reset_code, expires_at)
		VALUES ($1, $2, $3)
	`, passwordResetsTable)
	if _, err := r.db.ExecContext(ctx, createResetCodeQuery, userId, resetCode.String(), expiration); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "CreatePasswordResetRequest",
			UserID:    userId.String(),
			Entity:    "password_reset",
		}, err)
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
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "RemoveOutdatedPasswordResetRequests",
			UserID:    userId.String(),
			Entity:    "password_reset",
		}, err)
	}
}

func (r *Repository) ResetPassword(ctx context.Context, userId uuid.UUID, resetCode string, passwordHash string) error {

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "BeginResetPasswordTransaction",
			UserID:    userId.String(),
			Entity:    "password_reset",
		}, err)
		return fail.GrpcUnknown
	}

	defer tx.Rollback()
	var blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT blocked FROM users WHERE user_id=$1 FOR UPDATE`, userId).Scan(&blocked); err != nil {
		return fail.GrpcUnknown
	}
	// Check the proof before exposing blocked/deleting state.
	var valid bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM password_resets WHERE user_id=$1 AND reset_code=$2 AND used=false AND expires_at>NOW())`, userId, resetCode).Scan(&valid); err != nil {
		return fail.GrpcUnknown
	}
	if !valid {
		return authFail.GrpcInvalidResetPasswordCode
	}
	if blocked {
		return authFail.GrpcProfileIsBlocked
	}
	var deleting bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM delete_profile_requests WHERE user_id=$1)`, userId).Scan(&deleting); err != nil {
		return fail.GrpcUnknown
	}
	if deleting {
		return authFail.GrpcAccountDeleting
	}

	userResetCodeQuery := fmt.Sprintf(`
		UPDATE %s
		SET used=true
		WHERE user_id=$1 AND reset_code=$2 AND used=false AND expires_at>$3
	`, passwordResetsTable)

	res, err := tx.ExecContext(ctx, userResetCodeQuery, userId, resetCode, time.Now())
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "ValidatePasswordResetCode",
			UserID:    userId.String(),
			Entity:    "password_reset",
		}, err)
		return errorWithTransactionRollback(tx, authFail.GrpcInvalidResetPasswordCode)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "ReadValidatedPasswordResetCount",
			UserID:    userId.String(),
			Entity:    "password_reset",
		}, err)
		return errorWithTransactionRollback(tx, authFail.GrpcInvalidResetPasswordCode)
	}
	if rows == 0 {
		authlog.Default.PasswordResetCodeRejected(ctx, userId.String())
		return errorWithTransactionRollback(tx, authFail.GrpcInvalidResetPasswordCode)
	}

	changePasswordQuery := fmt.Sprintf(`
		UPDATE %s
		SET password=$1
		WHERE user_id=$2
	`, usersTable)

	if _, err := tx.ExecContext(ctx, changePasswordQuery, passwordHash, userId); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "ResetPassword",
			UserID:    userId.String(),
			Entity:    "user",
		}, err)
		return errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	return commitTransaction(ctx, tx)
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
	if err := row.Scan(&id); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "SetPassword",
			UserID:    userId.String(),
			Entity:    "user",
		}, err)
		return fail.GrpcUnknown
	}
	if id == "" {
		authlog.Default.PostgresLookupMissed(ctx, authlog.PostgresOperationData{
			Operation: "SetPassword",
			UserID:    userId.String(),
			Entity:    "user",
		})
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) GetPasswordResetUser(ctx context.Context, token string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRowContext(ctx, `SELECT user_id FROM password_resets WHERE reset_code=$1 AND used=false AND expires_at>NOW()`, token).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, authFail.GrpcInvalidResetPasswordCode
	}
	if err != nil {
		return uuid.Nil, fail.GrpcUnknown
	}
	return id, nil
}
