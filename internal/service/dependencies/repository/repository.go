package repository

import (
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"time"
)

type Data interface {
	CreateUser(credentials entity.CredentialsHash, activationCode *string, oauth entity.OAuth) (uuid.UUID, *entity.MessageData, error)
	GetAuthInfoById(userId uuid.UUID) (entity.AuthInfo, error)
	GetAuthInfoByEmail(email string) (entity.AuthInfo, error)
	GetAuthInfoByIdentifiers(identifiers entity.UserIdentifiers) (entity.AuthInfo, error)
	GetAuthInfoByNickname(nickname string) (entity.AuthInfo, error)
	GetAuthInfoByRefreshToken(refreshToken string) (entity.AuthInfo, error)
	GetAuthInfoByFirebaseId(firebaseId string) (entity.AuthInfo, error)
	GetAuthInfoByGoogleId(googleId string) (entity.AuthInfo, error)
	GetAuthInfoByVkId(vkId int64) (entity.AuthInfo, error)
	SetPassword(userId uuid.UUID, passwordHash string) error
	GetProfileActivationCode(userId uuid.UUID) (string, error)
	ActivateProfile(userId uuid.UUID, code string) error
	CreateSession(session entity.SessionInput) error
	GetSessions(userId uuid.UUID) []entity.SessionRawInfo
	UpdateSession(session entity.SessionInput, oldRefreshToken string) error
	DeleteSession(refreshToken string) error
	DeleteSessions(userId uuid.UUID, sessionIds []int64)
	DeleteAllSessions(userId uuid.UUID)
	DeleteOutdatedSessions(userId uuid.UUID, sessionsThreshold int)

	ConnectGoogle(userId uuid.UUID, googleId string) error
	DeleteGoogleConnection(userId uuid.UUID) error
	ConnectVk(userId uuid.UUID, vkId int64) error
	DeleteVkConnection(userId uuid.UUID) error

	IsFirebaseProfileConnected(firebaseId string) bool
	ConnectFirebase(userId uuid.UUID, firebaseId string, creationTimestamp time.Time) (*entity.MessageData, error)

	GetProfilesToDelete() []entity.DeleteProfileRequest
	GetDeleteProfileRequest(userId uuid.UUID) (entity.DeleteProfileRequest, error)
	RequestDeleteProfile(userId uuid.UUID, deleteSharedData bool) (time.Time, error)
	CancelProfileDeletion(userId uuid.UUID) error
	DeleteUser(userId uuid.UUID, deleteSharedData bool) (*entity.MessageData, error)

	GetNicknames(userIds []uuid.UUID) (map[uuid.UUID]string, error)
	SetNickname(userId uuid.UUID, nickname string) (string, error)

	CreatePasswordResetRequest(userId uuid.UUID, expiration time.Time) (uuid.UUID, error)
	ResetPassword(userId uuid.UUID, resetCode, passwordHash string) error
}

type MessageQueue interface {
	PublishProfilesMessage(msg *entity.MessageData) error
}
