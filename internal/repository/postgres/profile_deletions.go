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

func (r *Repository) GetProfilesToDelete() []entity.DeleteProfileRequest {
	var requests []entity.DeleteProfileRequest

	query := fmt.Sprintf(`
		SELECT user_id, with_shared_data, timestamp
		FROM %s
		WHERE timestamp<=$1
	`, deleteProfileRequestsTable)

	rows, err := r.db.Query(query, time.Now())
	if err != nil {
		log.Error("unable to get delete profile requests: ", err)
		return []entity.DeleteProfileRequest{}
	}

	for rows.Next() {
		var request entity.DeleteProfileRequest
		err = rows.Scan(&request.UserId, &request.WithSharedData, &request.Timestamp)
		if err != nil {
			log.Errorf("unable to parse delete profile request: %s", err)
			continue
		}
		requests = append(requests, request)
	}

	return requests
}

func (r *Repository) GetDeleteProfileRequest(userId uuid.UUID) (entity.DeleteProfileRequest, error) {
	var request entity.DeleteProfileRequest

	query := fmt.Sprintf(`
		SELECT user_id, with_shared_data, deletion_timestamp
		FROM %s
		WHERE user_id=$1
	`, deleteProfileRequestsTable)

	row := r.db.QueryRow(query, request.UserId)
	if err := row.Scan(&request.UserId, &request.WithSharedData, &request.Timestamp); err != nil {
		log.Warnf("delete profile request for user %s not found: %s", userId, err)
		return entity.DeleteProfileRequest{}, fail.GrpcNotFound
	}

	return request, nil
}

func (r *Repository) RequestDeleteProfile(userId uuid.UUID, deleteSharedData bool) (time.Time, error) {
	deletionTimestamp := time.Now().Add(r.profileDeleteOffset)

	query := fmt.Sprintf(`
		INSERT INTO %s (user_id, with_shared_data, deletion_timestamp)
		VALUES ($1, $2, $3)
	`, deleteProfileRequestsTable)

	if _, err := r.db.Exec(query, userId, deleteSharedData, deletionTimestamp); err != nil {
		if isUniqueViolationError(err) {
			request, err := r.GetDeleteProfileRequest(userId)
			if err != nil {
				return time.Time{}, fail.GrpcUnknown
			}
			return request.Timestamp, nil
		} else {
			log.Errorf("unable to add profile deletion request for user %s: %s", userId, err)
			return time.Time{}, fail.GrpcUnknown
		}
	}

	return deletionTimestamp, nil
}

func (r *Repository) CancelProfileDeletion(userId uuid.UUID) error {
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1
	`, deleteProfileRequestsTable)

	if _, err := r.db.Exec(query, userId); err != nil {
		log.Infof("unable to cancel delete profile %s request: %s", userId, err)
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) DeleteUser(userId uuid.UUID, deleteSharedData bool) (*entity.MessageData, error) {
	tx, err := r.db.Begin()
	if err != nil {
		log.Error("unable to begin transaction: ", err)
		return nil, fail.GrpcUnknown
	}

	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1
	`, usersTable)

	if _, err := tx.Exec(query, userId); err != nil {
		log.Infof("unable to delete user %s: %s", userId, err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	msg, err := r.addOutboxProfileDeletedMsg(userId, deleteSharedData, tx)
	if err != nil {
		return nil, err
	}

	return msg, commitTransaction(tx)
}

func (r *Repository) addOutboxProfileDeletedMsg(id uuid.UUID, deleteSharedData bool, tx *sql.Tx) (*entity.MessageData, error) {
	msgBody := api.MsgBodyProfileDeleted{
		UserId:           id.String(),
		DeleteSharedData: deleteSharedData,
	}
	var msgBodyBson, err = json.Marshal(msgBody)
	if err != nil {
		log.Error("unable to marshal profile deleted message body: ", err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}
	msg := entity.MessageData{
		Id:       uuid.New(),
		Exchange: api.ExchangeProfiles,
		Type:     api.MsgTypeProfileDeleted,
		Body:     msgBodyBson,
	}

	return &msg, r.createOutboxMsg(&msg, tx)
}
