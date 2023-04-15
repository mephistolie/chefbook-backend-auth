package postgres

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (r *Repository) ConnectFirebase(userId uuid.UUID, firebaseId string, creationTimestamp time.Time) error {
	tx, err := r.db.Begin()
	if err != nil {
		log.Error("unable to begin transaction: ", err)
		return fail.GrpcUnknown
	}

	clarifyRegistrationTimestampQuery := fmt.Sprintf(`
			UPDATE %s
			SET registered=$1
			WHERE user_id=$2
			RETURNING email
		`, usersTable)

	if _, err := tx.Exec(clarifyRegistrationTimestampQuery, creationTimestamp, userId); err != nil {
		log.Errorf("failed to set profile creation timestamp for user %s: %s", userId, err)
		if err := tx.Rollback(); err != nil {
			log.Error("unable to rollback transaction: ", err)
		}
		return fail.GrpcUnknown
	}

	addFirebaseConnectionQuery := fmt.Sprintf(`
			INSERT INTO %s (user_id, firebase_id)
			VALUES ($1, $2)
		`, firebaseTable)

	if _, err := tx.Exec(addFirebaseConnectionQuery, userId, firebaseId); err != nil {
		log.Errorf("failed to add Firebase connection fo user %s with firebase id %s: %s", userId, firebaseId, err)
		if err := tx.Rollback(); err != nil {
			log.Error("unable to rollback transaction: ", err)
		}
		return fail.GrpcUnknown
	}

	if err = tx.Commit(); err != nil {
		log.Error("unable to commit transaction: ", err)
		return fail.GrpcUnknown
	}

	return nil
}
