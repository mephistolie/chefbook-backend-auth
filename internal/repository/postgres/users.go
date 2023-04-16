package postgres

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/repository/postgres/dto"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (r *Repository) CreateUser(credentials entity.CredentialsHash, activationCode *string, oauth entity.OAuth) (uuid.UUID, error) {
	var id uuid.UUID
	if credentials.Id != nil {
		id = *credentials.Id
	} else {
		id = uuid.New()
	}

	tx, err := r.db.Begin()
	if err != nil {
		log.Error("unable to begin transaction: ", err)
		return uuid.UUID{}, fail.GrpcUnknown
	}

	createUserQuery := fmt.Sprintf(`
			INSERT INTO %s (user_id, email, password, activated)
			VALUES ($1, $2, $3, $4)
		`, usersTable)

	if _, err := tx.Exec(createUserQuery, id, credentials.Email, credentials.PasswordHash, activationCode == nil); err != nil {
		log.Errorf("unable to create user %s: %s", id, err)
		if err := tx.Rollback(); err != nil {
			log.Error("unable to rollback transaction: ", err)
		}
		return uuid.UUID{}, authFail.GrpcUnableCreateProfile
	}

	createOAuthQuery := fmt.Sprintf(`
			INSERT INTO %s (user_id, google_id, vk_id)
			VALUES ($1, $2, $3)
		`, oauthTable)

	if _, err := tx.Exec(createOAuthQuery, id, oauth.GoogleId, oauth.VkId); err != nil {
		log.Errorf("unable to create user %s oauth data: %s", id, err)
		if err := tx.Rollback(); err != nil {
			log.Error("unable to rollback transaction: ", err)
		}
		return uuid.UUID{}, authFail.GrpcUnableCreateProfile
	}

	if activationCode != nil {
		createActivationLinkQuery := fmt.Sprintf(`
			INSERT INTO %s (activation_code, user_id)
			VALUES ($1, $2)
			RETURNING user_id
		`, activationCodesTable)

		if _, err := tx.Exec(createActivationLinkQuery, *activationCode, id); err != nil {
			log.Errorf("unable to create user %s activation code: %s", id, err)
			if err := tx.Rollback(); err != nil {
				log.Error("unable to rollback transaction: ", err)
			}
			return uuid.UUID{}, authFail.GrpcUnableCreateProfile
		}
	}

	if err = tx.Commit(); err != nil {
		log.Error("unable to commit transaction: ", err)
		return uuid.UUID{}, fail.GrpcUnknown
	}

	return id, nil
}

func (r *Repository) GetAuthInfoById(userId uuid.UUID) (entity.AuthInfo, error) {
	info, err := r.getAuthInfoByCondition(fmt.Sprintf("%s.user_id=$1", usersTable), userId)
	if err != nil {
		log.Infof("user %s not found: %s", userId, err)
		return entity.AuthInfo{}, authFail.GrpcUserNotFound
	}
	return info, nil
}

func (r *Repository) GetAuthInfoByEmail(email string) (entity.AuthInfo, error) {
	info, err := r.getAuthInfoByCondition(fmt.Sprintf("%s.email=$1", usersTable), email)
	if err != nil {
		log.Infof("user with email %s not found: %s", email, err)
		return entity.AuthInfo{}, authFail.GrpcUserNotFound
	}
	return info, nil
}

func (r *Repository) GetAuthInfoByNickname(nickname string) (entity.AuthInfo, error) {
	info, err := r.getAuthInfoByCondition(fmt.Sprintf("%s.nickname=$1", usersTable), nickname)
	if err != nil {
		log.Infof("user with nickname %s not found: %s", nickname, err)
		return entity.AuthInfo{}, authFail.GrpcUserNotFound
	}
	return info, nil
}

func (r *Repository) GetAuthInfoByIdentifiers(identifiers entity.UserIdentifiers) (entity.AuthInfo, error) {
	var authInfo entity.AuthInfo
	err := authFail.GrpcUserNotFound

	if identifiers.UserId != nil {
		authInfo, err = r.GetAuthInfoById(*identifiers.UserId)
	}
	if err != nil && identifiers.Email != nil {
		authInfo, err = r.GetAuthInfoByEmail(*identifiers.Email)
	}
	if err != nil && identifiers.Nickname != nil {
		authInfo, err = r.GetAuthInfoByNickname(*identifiers.Nickname)
	}

	return authInfo, err
}

func (r *Repository) GetAuthInfoByRefreshToken(refreshToken string) (entity.AuthInfo, error) {
	var userId uuid.UUID
	var session entity.SessionInput

	getUserIdQuery := fmt.Sprintf(`
			SELECT user_id, expires_at
			FROM %s
			WHERE refresh_token=$1
		`, sessionsTable)

	row := r.db.QueryRow(getUserIdQuery, refreshToken)
	if err := row.Scan(&userId, &session.ExpiresAt); err != nil {
		log.Warnf("session for refresh token %s not found: %s", refreshToken, err)
		return entity.AuthInfo{}, authFail.GrpcSessionNotFound
	}

	if session.ExpiresAt.Before(time.Now()) {
		_ = r.DeleteSession(refreshToken)
		return entity.AuthInfo{}, authFail.GrpcSessionExpired
	}

	return r.GetAuthInfoById(userId)
}

func (r *Repository) GetAuthInfoByFirebaseId(firebaseId string) (entity.AuthInfo, error) {
	var userId uuid.UUID

	getUserIdQuery := fmt.Sprintf(`
			SELECT user_id
			FROM %s
			WHERE firebase_id=$1
		`, firebaseTable)

	if err := r.db.Get(&userId, getUserIdQuery, firebaseId); err != nil {
		return entity.AuthInfo{}, authFail.GrpcUserNotFound
	}

	return r.GetAuthInfoById(userId)
}

func (r *Repository) getAuthInfoByCondition(condition string, args ...interface{}) (entity.AuthInfo, error) {
	var info dto.AuthInfo
	query := fmt.Sprintf(`
			SELECT
				%[1]v.user_id, %[1]v.email, %[1]v.nickname, %[1]v.password, %[1]v.role, %[1]v.registered,
				%[1]v.activated, %[1]v.blocked, %[2]v.google_id, %[2]v.vk_id
			FROM
				%[1]v
			LEFT JOIN
				%[2]v ON %[1]v.user_id=%[2]v.user_id
			WHERE %[3]v
		`, usersTable, oauthTable, condition)
	if err := r.db.Get(&info, query, args...); err != nil {
		return entity.AuthInfo{}, err
	}
	return info.Entity(), nil
}

func (r *Repository) DeleteUser(userId uuid.UUID) error {
	query := fmt.Sprintf(`
			DELETE FROM %s
			WHERE user_id=$1
		`, usersTable)

	if _, err := r.db.Exec(query, userId); err != nil {
		log.Infof("unable to delete user %s: %s", userId, err)
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) SetNickname(userId uuid.UUID, nickname string) (string, error) {
	var email string

	query := fmt.Sprintf(`
			UPDATE %s
			SET nickname=$1
			WHERE user_id=$2
			RETURNING email
		`, usersTable)

	if err := r.db.Get(&email, query, nickname, userId); err != nil {
		log.Infof("nickname %s is occupied: %s", nickname, err)
		return "", authFail.GrpcNicknameOccupied
	}

	return email, nil
}
