package repository

import (
	"context"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"time"
)

type Data interface {
	CreateUser(ctx context.Context, credentials entity.CredentialsHash, activationCode *string, oauth entity.OAuth) (uuid.UUID, *entity.MessageData, error)
	GetAuthInfoById(ctx context.Context, userId uuid.UUID) (entity.AuthInfo, error)
	GetAuthInfoByEmail(ctx context.Context, email string) (entity.AuthInfo, error)
	GetAuthInfoByIdentifiers(ctx context.Context, identifiers entity.UserIdentifiers) (entity.AuthInfo, error)
	GetAuthInfoByNickname(ctx context.Context, nickname string) (entity.AuthInfo, error)
	GetAuthInfoByRefreshToken(ctx context.Context, refreshToken string) (entity.AuthInfo, error)
	GetAuthInfoByFirebaseId(ctx context.Context, firebaseId string) (entity.AuthInfo, error)
	GetAuthInfoByGoogleId(ctx context.Context, googleId string) (entity.AuthInfo, error)
	GetAuthInfoByVkId(ctx context.Context, vkId int64) (entity.AuthInfo, error)
	SetPassword(ctx context.Context, userId uuid.UUID, passwordHash string) error
	GetProfileActivationCode(ctx context.Context, userId uuid.UUID) (string, error)
	ActivateProfile(ctx context.Context, userId uuid.UUID, code string) error
	CreateSession(ctx context.Context, session entity.SessionInput) error
	GetSessions(ctx context.Context, userId uuid.UUID) []entity.SessionRawInfo
	UpdateSession(ctx context.Context, session entity.SessionInput, oldRefreshToken string) error
	DeleteSession(ctx context.Context, refreshToken string) error
	DeleteSessions(ctx context.Context, userId uuid.UUID, sessionIds []int64)
	DeleteAllSessions(ctx context.Context, userId uuid.UUID)
	DeleteOutdatedSessions(ctx context.Context, userId uuid.UUID, sessionsThreshold int)

	ConnectGoogle(ctx context.Context, userId uuid.UUID, googleId string) error
	DeleteGoogleConnection(ctx context.Context, userId uuid.UUID) error
	ConnectVk(ctx context.Context, userId uuid.UUID, vkId int64) error
	DeleteVkConnection(ctx context.Context, userId uuid.UUID) error

	IsFirebaseProfileConnected(ctx context.Context, firebaseId string) bool
	ConnectFirebase(ctx context.Context, userId uuid.UUID, firebaseId string, creationTimestamp time.Time) (*entity.MessageData, error)

	GetProfilesToDelete(ctx context.Context) []entity.DeleteProfileRequest
	GetDeleteProfileRequest(ctx context.Context, userId uuid.UUID) (entity.DeleteProfileRequest, error)
	RequestDeleteProfile(ctx context.Context, userId uuid.UUID, deleteSharedData bool) (time.Time, error)
	CancelProfileDeletion(ctx context.Context, userId uuid.UUID) error
	DeleteUser(ctx context.Context, userId uuid.UUID, deleteSharedData bool) (*entity.MessageData, error)

	GetNicknames(ctx context.Context, userIds []uuid.UUID) (map[uuid.UUID]string, error)
	SetNickname(ctx context.Context, userId uuid.UUID, nickname string) (string, error)

	CreatePasswordResetRequest(ctx context.Context, userId uuid.UUID, expiration time.Time) (uuid.UUID, error)
	ResetPassword(ctx context.Context, userId uuid.UUID, resetCode, passwordHash string) error
}

type MessageQueue interface {
	PublishProfilesMessage(msg *entity.MessageData) error
}
