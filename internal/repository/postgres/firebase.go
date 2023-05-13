package postgres

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (r *Repository) IsFirebaseProfileConnected(firebaseId string) bool {
	var userId uuid.UUID

	query := fmt.Sprintf(`
			SELECT user_id
			FROM %s
			WHERE firebase_id=$1
		`, firebaseTable)

	if err := r.db.Get(&userId, query, firebaseId); err != nil || len(userId.String()) == 0 {
		return false
	}
	return true
}

func (r *Repository) ConnectFirebase(userId uuid.UUID, firebaseId string, creationTimestamp time.Time) (*entity.MessageData, error) {
	tx, err := r.db.Begin()
	if err != nil {
		log.Error("unable to begin transaction: ", err)
		return nil, fail.GrpcUnknown
	}

	clarifyRegistrationTimestampQuery := fmt.Sprintf(`
			UPDATE %s
			SET registered=$1
			WHERE user_id=$2
		`, usersTable)

	if _, err := tx.Exec(clarifyRegistrationTimestampQuery, creationTimestamp, userId); err != nil {
		log.Errorf("failed to set profile creation timestamp for user %s: %s", userId, err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	addFirebaseConnectionQuery := fmt.Sprintf(`
			INSERT INTO %s (user_id, firebase_id)
			VALUES ($1, $2)
		`, firebaseTable)

	if _, err := tx.Exec(addFirebaseConnectionQuery, userId, firebaseId); err != nil {
		log.Errorf("failed to add Firebase connection fo user %s with firebase id %s: %s", userId, firebaseId, err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	msg, err := r.addOutboxProfileFirebaseImportMsg(userId, firebaseId, tx)
	if err != nil {
		return nil, err
	}

	return msg, commitTransaction(tx)
}

func (r *Repository) addOutboxProfileFirebaseImportMsg(id uuid.UUID, firebaseId string, tx *sql.Tx) (*entity.MessageData, error) {
	msgBody := api.MsgBodyProfileFirebaseImport{
		UserId:     id.String(),
		FirebaseId: firebaseId,
	}
	var msgBodyBson, err = json.Marshal(msgBody)
	if err != nil {
		log.Error("unable to marshal firebase import message body: ", err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}
	msgInfo := entity.MessageData{
		Id:       uuid.New(),
		Exchange: api.ExchangeProfiles,
		Type:     api.MsgTypeProfileFirebaseImport,
		Body:     msgBodyBson,
	}

	return &msgInfo, r.createOutboxMsg(&msgInfo, tx)
}
