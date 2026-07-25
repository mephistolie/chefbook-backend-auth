package postgres

import (
	"context"
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

func (r *Repository) GetProfilesToDelete(ctx context.Context) []entity.DeleteProfileRequest {
	var requests []entity.DeleteProfileRequest

	query := fmt.Sprintf(`
		SELECT user_id, with_shared_data, deletion_timestamp
		FROM %s
		WHERE deletion_timestamp<=$1
	`, deleteProfileRequestsTable)

	rows, err := r.db.QueryContext(ctx, query, time.Now())
	if err != nil {
		log.AutoError("unable to get delete profile requests: ", err)
		return []entity.DeleteProfileRequest{}
	}

	for rows.Next() {
		var request entity.DeleteProfileRequest
		err = rows.Scan(&request.UserId, &request.WithSharedData, &request.Timestamp)
		if err != nil {
			log.AutoErrorf("unable to parse delete profile request: %s", err)
			continue
		}
		requests = append(requests, request)
	}

	return requests
}

func (r *Repository) GetDeleteProfileRequest(ctx context.Context, userId uuid.UUID) (entity.DeleteProfileRequest, error) {
	var request entity.DeleteProfileRequest

	query := fmt.Sprintf(`
		SELECT user_id, with_shared_data, deletion_timestamp
		FROM %s
		WHERE user_id=$1
	`, deleteProfileRequestsTable)

	row := r.db.QueryRowContext(ctx, query, userId)
	if err := row.Scan(&request.UserId, &request.WithSharedData, &request.Timestamp); err != nil {
		log.AutoWarnf("delete profile request for user %s not found: %s", userId, err)
		return entity.DeleteProfileRequest{}, fail.GrpcNotFound
	}

	return request, nil
}

func (r *Repository) RequestDeleteProfile(ctx context.Context, userId uuid.UUID, deleteSharedData bool) (time.Time, error) {
	deletionTimestamp := time.Now().Add(r.profileDeleteOffset)

	query := fmt.Sprintf(`
		INSERT INTO %s (user_id, with_shared_data, deletion_timestamp)
		VALUES ($1, $2, $3)
	`, deleteProfileRequestsTable)

	if _, err := r.db.ExecContext(ctx, query, userId, deleteSharedData, deletionTimestamp); err != nil {
		if isUniqueViolationError(err) {
			request, err := r.GetDeleteProfileRequest(ctx, userId)
			if err != nil {
				return time.Time{}, fail.GrpcUnknown
			}
			return request.Timestamp, nil
		} else {
			log.AutoErrorf("unable to add profile deletion request for user %s: %s", userId, err)
			return time.Time{}, fail.GrpcUnknown
		}
	}

	return deletionTimestamp, nil
}

func (r *Repository) CancelProfileDeletion(ctx context.Context, userId uuid.UUID) error {
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1
	`, deleteProfileRequestsTable)

	if _, err := r.db.ExecContext(ctx, query, userId); err != nil {
		log.AutoInfof("unable to cancel delete profile %s request: %s", userId, err)
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) DeleteUser(ctx context.Context, userId uuid.UUID, deleteSharedData bool) (*entity.MessageData, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		log.AutoError("unable to begin transaction: ", err)
		return nil, fail.GrpcUnknown
	}

	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1
	`, usersTable)

	if _, err := tx.ExecContext(ctx, query, userId); err != nil {
		log.AutoInfof("unable to delete user %s: %s", userId, err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	msg, err := r.addOutboxProfileDeletedMsg(ctx, userId, deleteSharedData, tx)
	if err != nil {
		return nil, err
	}

	return msg, commitTransaction(tx)
}

func (r *Repository) addOutboxProfileDeletedMsg(ctx context.Context, id uuid.UUID, deleteSharedData bool, tx *sql.Tx) (*entity.MessageData, error) {
	msgBody := api.MsgBodyProfileDeleted{
		UserId:           id.String(),
		DeleteSharedData: deleteSharedData,
	}
	var msgBodyBson, err = json.Marshal(msgBody)
	if err != nil {
		log.AutoError("unable to marshal profile deleted message body: ", err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}
	msg := entity.MessageData{
		Id:       uuid.New(),
		Exchange: api.ExchangeProfiles,
		Type:     api.MsgTypeProfileDeleted,
		Body:     msgBodyBson,
	}

	return &msg, r.createOutboxMsg(ctx, &msg, tx)
}
