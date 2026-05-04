package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/repository/postgres/dto"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (r *Repository) CreateUser(
	ctx context.Context,
	credentials entity.CredentialsHash,
	activationCode *string,
	oauth entity.OAuth,
) (uuid.UUID, *entity.MessageData, error) {
	log.Infof("creating user for email %s...", credentials.Email)
	var id uuid.UUID
	if credentials.Id != nil {
		id = *credentials.Id
	} else {
		id = uuid.New()
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		log.Error("unable to begin transaction: ", err)
		return uuid.UUID{}, nil, fail.GrpcUnknown
	}

	if err = r.addUsersRow(ctx, id, credentials, activationCode == nil, tx); err != nil {
		return uuid.UUID{}, nil, err
	}
	if err = r.addOauthRow(ctx, id, oauth, tx); err != nil {
		return uuid.UUID{}, nil, err
	}
	if err = r.addActivationCodeRow(ctx, id, activationCode, tx); err != nil {
		return uuid.UUID{}, nil, err
	}

	msg, err := r.addOutboxProfileCreatedMsg(ctx, id, tx)
	if err != nil {
		return uuid.UUID{}, nil, err
	}

	return id, msg, commitTransaction(tx)
}

func (r *Repository) addUsersRow(ctx context.Context, id uuid.UUID, credentials entity.CredentialsHash, activated bool, tx *sql.Tx) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (user_id, email, password, activated)
		VALUES ($1, $2, $3, $4)
	`, usersTable)

	if _, err := tx.ExecContext(ctx, query, id, credentials.Email, credentials.PasswordHash, activated); err != nil {
		log.Errorf("unable to create user %s: %s", id, err)
		return errorWithTransactionRollback(tx, authFail.GrpcUnableCreateProfile)
	}

	return nil
}

func (r *Repository) addOauthRow(ctx context.Context, id uuid.UUID, oauth entity.OAuth, tx *sql.Tx) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (user_id, google_id, vk_id)
		VALUES ($1, $2, $3)
	`, oauthTable)

	if _, err := tx.ExecContext(ctx, query, id, oauth.GoogleId, oauth.VkId); err != nil {
		log.Errorf("unable to create user %s oauth data: %s", id, err)
		return errorWithTransactionRollback(tx, authFail.GrpcUnableCreateProfile)
	}

	return nil
}

func (r *Repository) addActivationCodeRow(ctx context.Context, id uuid.UUID, activationCode *string, tx *sql.Tx) error {
	if activationCode != nil {
		query := fmt.Sprintf(`
			INSERT INTO %s (activation_code, user_id)
			VALUES ($1, $2)
		`, activationCodesTable)

		if _, err := tx.ExecContext(ctx, query, *activationCode, id); err != nil {
			log.Errorf("unable to create user %s activation code: %s", id, err)
			return errorWithTransactionRollback(tx, authFail.GrpcUnableCreateProfile)
		}
	}

	return nil
}

func (r *Repository) addOutboxProfileCreatedMsg(ctx context.Context, id uuid.UUID, tx *sql.Tx) (*entity.MessageData, error) {
	msgBody := api.MsgBodyProfileCreated{
		UserId: id.String(),
	}
	var msgBodyBson, err = json.Marshal(msgBody)
	if err != nil {
		log.Error("unable to marshal profile created message body: ", err)
		return nil, errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}
	msg := entity.MessageData{
		Id:       uuid.New(),
		Exchange: api.ExchangeProfiles,
		Type:     api.MsgTypeProfileCreated,
		Body:     msgBodyBson,
	}

	return &msg, r.createOutboxMsg(ctx, &msg, tx)
}

func (r *Repository) GetAuthInfoById(ctx context.Context, userId uuid.UUID) (entity.AuthInfo, error) {
	info, err := r.getAuthInfoByCondition(ctx, fmt.Sprintf("%s.user_id=$1", usersTable), userId)
	if err != nil {
		log.Infof("user %s not found: %s", userId, err)
		return entity.AuthInfo{}, authFail.GrpcUserNotFound
	}
	return info, nil
}

func (r *Repository) GetAuthInfoByEmail(ctx context.Context, email string) (entity.AuthInfo, error) {
	info, err := r.getAuthInfoByCondition(ctx, fmt.Sprintf("%s.email=$1", usersTable), email)
	if err != nil {
		log.Infof("user with email %s not found: %s", email, err)
		return entity.AuthInfo{}, authFail.GrpcUserNotFound
	}
	return info, nil
}

func (r *Repository) GetAuthInfoByNickname(ctx context.Context, nickname string) (entity.AuthInfo, error) {
	info, err := r.getAuthInfoByCondition(ctx, fmt.Sprintf("%s.nickname=$1", usersTable), nickname)
	if err != nil {
		log.Infof("user with nickname %s not found: %s", nickname, err)
		return entity.AuthInfo{}, authFail.GrpcUserNotFound
	}
	return info, nil
}

func (r *Repository) GetAuthInfoByIdentifiers(ctx context.Context, identifiers entity.UserIdentifiers) (entity.AuthInfo, error) {
	var authInfo entity.AuthInfo
	err := authFail.GrpcUserNotFound

	if identifiers.UserId != nil {
		authInfo, err = r.GetAuthInfoById(ctx, *identifiers.UserId)
	}
	if err != nil && identifiers.Email != nil {
		authInfo, err = r.GetAuthInfoByEmail(ctx, *identifiers.Email)
	}
	if err != nil && identifiers.Nickname != nil {
		authInfo, err = r.GetAuthInfoByNickname(ctx, *identifiers.Nickname)
	}

	return authInfo, err
}

func (r *Repository) GetAuthInfoByRefreshToken(ctx context.Context, refreshToken string) (entity.AuthInfo, error) {
	var userId uuid.UUID
	var session entity.SessionInput

	getUserIdQuery := fmt.Sprintf(`
		SELECT user_id, expires_at
		FROM %s
		WHERE refresh_token=$1
	`, sessionsTable)

	row := r.db.QueryRowContext(ctx, getUserIdQuery, refreshToken)
	if err := row.Scan(&userId, &session.ExpiresAt); err != nil {
		log.Warnf("session for refresh token %s not found: %s", refreshToken, err)
		return entity.AuthInfo{}, authFail.GrpcSessionNotFound
	}

	if session.ExpiresAt.Before(time.Now()) {
		_ = r.DeleteSession(ctx, refreshToken)
		return entity.AuthInfo{}, authFail.GrpcSessionExpired
	}

	return r.GetAuthInfoById(ctx, userId)
}

func (r *Repository) GetAuthInfoByFirebaseId(ctx context.Context, firebaseId string) (entity.AuthInfo, error) {
	var userId uuid.UUID

	getUserIdQuery := fmt.Sprintf(`
			SELECT user_id
			FROM %s
			WHERE firebase_id=$1
		`, firebaseTable)

	if err := r.db.GetContext(ctx, &userId, getUserIdQuery, firebaseId); err != nil {
		return entity.AuthInfo{}, authFail.GrpcUserNotFound
	}

	return r.GetAuthInfoById(ctx, userId)
}

func (r *Repository) getAuthInfoByCondition(ctx context.Context, condition string, args ...interface{}) (entity.AuthInfo, error) {
	var info dto.AuthInfo
	query := fmt.Sprintf(`
		SELECT
			%[1]v.user_id, %[1]v.email, %[1]v.nickname, %[1]v.password, %[1]v.role, %[1]v.registered,
			%[1]v.activated, %[1]v.blocked, %[2]v.google_id, %[2]v.vk_id, %[3]v.deletion_timestamp
		FROM
			%[1]v
		LEFT JOIN
			%[2]v ON %[1]v.user_id=%[2]v.user_id
		LEFT JOIN
			%[3]v ON %[1]v.user_id=%[3]v.user_id
		WHERE %[4]v
	`, usersTable, oauthTable, deleteProfileRequestsTable, condition)
	if err := r.db.GetContext(ctx, &info, query, args...); err != nil {
		return entity.AuthInfo{}, err
	}
	return info.Entity(), nil
}

func (r *Repository) GetNicknames(ctx context.Context, userIds []uuid.UUID) (map[uuid.UUID]string, error) {
	nicknames := make(map[uuid.UUID]string)

	query := fmt.Sprintf(`
		SELECT user_id, nickname
		FROM %s
		WHERE user_id=ANY($1)
	`, usersTable)

	rows, err := r.db.QueryContext(ctx, query, userIds)
	if err != nil {
		log.Error("unable to get nicknames for users: ", err)
		return nil, fail.GrpcNotFound
	}

	for rows.Next() {
		var userId uuid.UUID
		var nickname *string

		if err = rows.Scan(&userId, &nickname); err != nil {
			log.Error("unable to parse nickname and email for user: ", err)
			continue
		}

		if nickname != nil {
			nicknames[userId] = *nickname
		}
	}

	return nicknames, nil
}

func (r *Repository) SetNickname(ctx context.Context, userId uuid.UUID, nickname string) (string, error) {
	var email string

	query := fmt.Sprintf(`
		UPDATE %s
		SET nickname=$1
		WHERE user_id=$2
		RETURNING email
	`, usersTable)

	if err := r.db.GetContext(ctx, &email, query, nickname, userId); err != nil {
		log.Infof("nickname %s is occupied: %s", nickname, err)
		return "", authFail.GrpcNicknameOccupied
	}

	return email, nil
}
