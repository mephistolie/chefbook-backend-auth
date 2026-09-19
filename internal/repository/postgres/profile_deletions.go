package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"errors"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
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
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "GetProfilesToDelete",
			Entity:    "profile_deletion_request",
		}, err)
		return []entity.DeleteProfileRequest{}
	}

	defer rows.Close()
	for rows.Next() {
		var request entity.DeleteProfileRequest
		err = rows.Scan(&request.UserId, &request.WithSharedData, &request.Timestamp)
		if err != nil {
			authlog.Default.PostgresRowScanFailed(ctx, authlog.PostgresOperationData{
				Operation: "GetProfilesToDelete",
				Entity:    "profile_deletion_request",
			}, err)
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
		authlog.Default.PostgresLookupWarned(ctx, authlog.PostgresOperationData{
			Operation: "GetDeleteProfileRequest",
			UserID:    userId.String(),
			Entity:    "profile_deletion_request",
		})
		if errors.Is(err, sql.ErrNoRows) {
			return entity.DeleteProfileRequest{}, authFail.GrpcDeletionNotFound
		}
		return entity.DeleteProfileRequest{}, fail.GrpcUnknown
	}

	return request, nil
}

func (r *Repository) RequestDeleteProfile(ctx context.Context, id uuid.UUID, policy bool) (entity.DeleteProfileRequest, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return entity.DeleteProfileRequest{}, fail.GrpcUnknown
	}
	defer tx.Rollback()
	if err = lockDeletionUser(ctx, tx, id); err != nil {
		return entity.DeleteProfileRequest{}, err
	}
	existing, err := lockDeletion(ctx, tx, id)
	if err == nil {
		return existing, nil
	}
	if err != authFail.GrpcDeletionNotFound {
		return entity.DeleteProfileRequest{}, err
	}
	deadline := time.Now().Add(r.profileDeleteOffset)
	if _, err = tx.ExecContext(ctx, `INSERT INTO delete_profile_requests(user_id,with_shared_data,deletion_timestamp) VALUES($1,$2,$3)`, id, policy, deadline); err != nil {
		return entity.DeleteProfileRequest{}, fail.GrpcUnknown
	}
	return entity.DeleteProfileRequest{UserId: id, WithSharedData: policy, Timestamp: deadline}, commitTransaction(ctx, tx)
}
func lockDeletionUser(ctx context.Context, tx *sql.Tx, id uuid.UUID) error {
	var blocked bool
	err := tx.QueryRowContext(ctx, `SELECT blocked FROM users WHERE user_id=$1 FOR UPDATE`, id).Scan(&blocked)
	if errors.Is(err, sql.ErrNoRows) {
		return authFail.GrpcUserNotFound
	}
	if err != nil {
		return fail.GrpcUnknown
	}
	if blocked {
		return authFail.GrpcProfileIsBlocked
	}
	return nil
}

func (r *Repository) UpdateProfileDeletion(ctx context.Context, userId uuid.UUID, policy bool) (entity.DeleteProfileRequest, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return entity.DeleteProfileRequest{}, fail.GrpcUnknown
	}
	defer tx.Rollback()
	if err = lockDeletionUser(ctx, tx, userId); err != nil {
		return entity.DeleteProfileRequest{}, err
	}
	request, err := lockDeletion(ctx, tx, userId)
	if err != nil {
		return request, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE delete_profile_requests SET with_shared_data=$2 WHERE user_id=$1`, userId, policy); err != nil {
		return request, fail.GrpcUnknown
	}
	request.WithSharedData = policy
	return request, commitTransaction(ctx, tx)
}
func lockDeletion(ctx context.Context, tx *sql.Tx, id uuid.UUID) (entity.DeleteProfileRequest, error) {
	var request entity.DeleteProfileRequest
	err := tx.QueryRowContext(ctx, `SELECT user_id,with_shared_data,deletion_timestamp FROM delete_profile_requests WHERE user_id=$1 FOR UPDATE`, id).Scan(&request.UserId, &request.WithSharedData, &request.Timestamp)
	if errors.Is(err, sql.ErrNoRows) {
		return request, authFail.GrpcDeletionNotFound
	}
	if err != nil {
		return request, fail.GrpcUnknown
	}
	if !request.Timestamp.After(time.Now()) {
		return request, authFail.GrpcDeletionExpired
	}
	return request, nil
}
func (r *Repository) CancelProfileDeletion(ctx context.Context, userId uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fail.GrpcUnknown
	}
	defer tx.Rollback()
	if err = lockDeletionUser(ctx, tx, userId); err != nil {
		return err
	}
	_, err = lockDeletion(ctx, tx, userId)
	if err == authFail.GrpcDeletionNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM delete_profile_requests WHERE user_id=$1`, userId); err != nil {
		return fail.GrpcUnknown
	}
	return commitTransaction(ctx, tx)
}

func (r *Repository) DeleteUser(ctx context.Context, userId uuid.UUID, deleteSharedData bool) (*entity.MessageData, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "BeginDeleteUserTransaction",
			UserID:    userId.String(),
			Entity:    "user",
		}, err)
		return nil, fail.GrpcUnknown
	}

	defer tx.Rollback()
	// User-before-request lock order matches request/cancel/update and email workflows.
	var existing uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM users WHERE user_id=$1 FOR UPDATE`, userId).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fail.GrpcUnknown
	}
	var deadline time.Time
	err = tx.QueryRowContext(ctx, `SELECT with_shared_data,deletion_timestamp FROM delete_profile_requests WHERE user_id=$1 FOR UPDATE`, userId).Scan(&deleteSharedData, &deadline)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fail.GrpcUnknown
	}
	if deadline.After(time.Now()) {
		return nil, nil
	}

	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1
	`, usersTable)

	if _, err := tx.ExecContext(ctx, query, userId); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "DeleteUser",
			UserID:    userId.String(),
			Entity:    "user",
		}, err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	msg, err := r.addOutboxProfileDeletedMsg(ctx, userId, deleteSharedData, tx)
	if err != nil {
		return nil, err
	}

	return msg, commitTransaction(ctx, tx)
}

func (r *Repository) addOutboxProfileDeletedMsg(ctx context.Context, id uuid.UUID, deleteSharedData bool, tx *sql.Tx) (*entity.MessageData, error) {
	msgBody := api.MsgBodyProfileDeleted{
		UserId:           id.String(),
		DeleteSharedData: deleteSharedData,
	}
	var msgBodyBson, err = json.Marshal(msgBody)
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "MarshalProfileDeletedOutboxMessage",
			UserID:    id.String(),
			Entity:    "outbox_message",
		}, err)
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
