package postgres

import (
	"fmt"
	"github.com/google/uuid"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (r *Repository) CreatePasswordResetRequest(userId uuid.UUID, expiration time.Time) (uuid.UUID, error) {
	resetCode := uuid.UUID{}

	r.removeOutdatedPasswordResetRequests(userId)

	getExistingResetCodeQuery := fmt.Sprintf(`
			SELECT reset_code
			FROM %s
			WHERE user_id=$1 AND used=false
		`, passwordResetsTable)
	if err := r.db.Get(&resetCode, getExistingResetCodeQuery, userId); err == nil {
		log.Infof("found existing password reset code for user %s", userId)
		return resetCode, nil
	}

	resetCode = uuid.New()
	createResetCodeQuery := fmt.Sprintf(`
			INSERT INTO %s (user_id, reset_code, expires_at)
			VALUES ($1, $2, $3)
		`, passwordResetsTable)
	if _, err := r.db.Exec(createResetCodeQuery, userId, resetCode.String(), expiration); err != nil {
		log.Errorf("error while creating reset code for user %s: %s", userId, err)
		return uuid.UUID{}, fail.GrpcUnknown
	}

	return resetCode, nil
}

func (r *Repository) removeOutdatedPasswordResetRequests(userId uuid.UUID) {
	query := fmt.Sprintf(`
			DELETE FROM %[1]v
			WHERE user_id=$1 AND used=false AND expires_at<=$2
		`, passwordResetsTable)

	if _, err := r.db.Exec(query, userId, time.Now()); err != nil {
		log.Errorf("error while delete outdated reset codes for user %s: %s", userId, err)
	}
}

func (r *Repository) ResetPassword(userId uuid.UUID, resetCode string, passwordHash string) error {

	tx, err := r.db.Begin()
	if err != nil {
		log.Error("unable to begin transaction: ", err)
		return fail.GrpcUnknown
	}

	userResetCodeQuery := fmt.Sprintf(`
			UPDATE %s
			SET used=true
			WHERE user_id=$1 AND reset_code=$2
		`, passwordResetsTable)

	if _, err := tx.Exec(userResetCodeQuery, userId, resetCode); err != nil {
		log.Errorf("invalid reset code %s for user %s: %s", resetCode, userId, err)
		if err := tx.Rollback(); err != nil {
			return fail.GrpcUnknown
		}
		return authFail.GrpcInvalidResetPasswordCode
	}

	changePasswordQuery := fmt.Sprintf(`
			UPDATE %s
			SET password=$1
			WHERE user_id=$2
			RETURNING user_id
		`, usersTable)

	if _, err := r.db.Exec(changePasswordQuery, passwordHash, userId); err != nil {
		log.Errorf("error while updating password for user %s: %s", userId, err)
		if err := tx.Rollback(); err != nil {
			log.Error("unable to rollback transaction: ", err)
		}
		return fail.GrpcUnknown
	}

	if err := tx.Commit(); err != nil {
		log.Error("unable to commit transaction: ", err)
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) SetPassword(userId uuid.UUID, passwordHash string) error {
	id := ""

	changePasswordQuery := fmt.Sprintf(`
			UPDATE %s
			SET password=$1
			WHERE user_id=$2
			RETURNING user_id
		`, usersTable)

	row := r.db.QueryRow(changePasswordQuery, passwordHash, userId)
	if err := row.Scan(&id); err != nil || id == "" {
		log.Errorf("error while updating password for user %s: %s", userId, err)
		return fail.GrpcUnknown
	}

	return nil
}
