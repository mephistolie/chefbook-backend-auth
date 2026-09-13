package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) IsFirebaseProfileConnected(ctx context.Context, firebaseId string) bool {
	var userId uuid.UUID

	query := fmt.Sprintf(`
		SELECT user_id
		FROM %s
		WHERE firebase_id=$1
	`, firebaseTable)

	if err := r.db.GetContext(ctx, &userId, query, firebaseId); err != nil || len(userId.String()) == 0 {
		return false
	}
	return true
}

func (r *Repository) ConnectFirebase(ctx context.Context, userId uuid.UUID, firebaseId string, creationTimestamp time.Time) (*entity.MessageData, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "BeginConnectFirebaseTransaction",
			UserID:    userId.String(),
			Entity:    "firebase_connection",
		}, err)
		return nil, fail.GrpcUnknown
	}

	clarifyRegistrationTimestampQuery := fmt.Sprintf(`
		UPDATE %s
		SET registered=$1
		WHERE user_id=$2
	`, usersTable)

	if _, err := tx.ExecContext(ctx, clarifyRegistrationTimestampQuery, creationTimestamp, userId); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "SetFirebaseProfileCreationTimestamp",
			UserID:    userId.String(),
			Entity:    "user",
		}, err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	addFirebaseConnectionQuery := fmt.Sprintf(`
		INSERT INTO %s (user_id, firebase_id)
		VALUES ($1, $2)
	`, firebaseTable)

	if _, err := tx.ExecContext(ctx, addFirebaseConnectionQuery, userId, firebaseId); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "ConnectFirebase",
			UserID:    userId.String(),
			Entity:    "firebase_connection",
		}, err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	msg, err := r.addOutboxProfileFirebaseImportMsg(ctx, userId, firebaseId, tx)
	if err != nil {
		return nil, err
	}

	return msg, commitTransaction(ctx, tx)
}

func (r *Repository) addOutboxProfileFirebaseImportMsg(ctx context.Context, id uuid.UUID, firebaseId string, tx *sql.Tx) (*entity.MessageData, error) {
	msgBody := api.MsgBodyProfileFirebaseImport{
		UserId:     id.String(),
		FirebaseId: firebaseId,
	}
	var msgBodyBson, err = json.Marshal(msgBody)
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "MarshalFirebaseImportOutboxMessage",
			UserID:    id.String(),
			Entity:    "outbox_message",
		}, err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}
	msgInfo := entity.MessageData{
		Id:       uuid.New(),
		Exchange: api.ExchangeProfiles,
		Type:     api.MsgTypeProfileFirebaseImport,
		Body:     msgBodyBson,
	}

	return &msgInfo, r.createOutboxMsg(ctx, &msgInfo, tx)
}
