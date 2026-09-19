package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-auth/internal/repository/grpc"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	emailService "github.com/mephistolie/chefbook-backend-auth/internal/service/email"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	oauthService "github.com/mephistolie/chefbook-backend-auth/internal/service/oauth"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/password"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/profile_deletion"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/reauthentication"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/session"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/username"
	"github.com/mephistolie/chefbook-backend-auth/pkg/ip"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/google"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/vk"
	firebase "github.com/mephistolie/chefbook-backend-common/firebase"
	"github.com/mephistolie/chefbook-backend-common/hash"
	"github.com/mephistolie/chefbook-backend-common/tokens"
	"strconv"
	"time"
)

type Service struct {
	Email           *emailService.Service
	Session         Session
	OAuth           OAuth
	Password        Password
	Username        Username
	ProfileDeletion ProfileDeletion
}

type Session interface {
	SignUp(ctx context.Context, credentials entity.SignUpCredentials, activationLinkPattern string) (uuid.UUID, bool, error)
	ActivateProfile(ctx context.Context, userId uuid.UUID, code string) error
	SignIn(ctx context.Context, credentials entity.SignInCredentials, client entity.ClientData) (entity.Tokens, error)
	SignInGoogle(ctx context.Context, credentials entity.OAuthCredentials, client entity.ClientData, redirectUrl string) (entity.Tokens, error)
	SignInGoogleIdToken(ctx context.Context, token string, client entity.ClientData) (entity.Tokens, error)
	SignInVk(ctx context.Context, credentials entity.OAuthCredentials, client entity.ClientData, redirectUri string) (entity.Tokens, error)
	GetAccessTokenPublicKey() []byte
	Refresh(ctx context.Context, refreshToken, ip, userAgent string) (entity.Tokens, error)
	SignOut(ctx context.Context, refreshToken string) error
	GetAuthInfo(ctx context.Context, identifiers entity.UserIdentifiers) (entity.AuthInfo, error)
	GetAll(ctx context.Context, userId uuid.UUID) ([]entity.SessionInfo, error)
	DeleteMultiple(ctx context.Context, userId uuid.UUID, sessionIds []int64) error
}

type OAuth interface {
	ConnectGoogleToken(context.Context, uuid.UUID, string) (bool, error)
	GenerateGoogleLink(ctx context.Context, redirectUrl string) (string, error)
	ConnectGoogle(ctx context.Context, userId uuid.UUID, code, state, redirectUri string) (bool, error)
	DeleteGoogleConnection(ctx context.Context, userId uuid.UUID) error
	GenerateVkLink(ctx context.Context, display, responseType, redirectUrl string) (string, error)
	ConnectVk(ctx context.Context, userId uuid.UUID, code, state, redirectUri string) (bool, error)
	DeleteVkConnection(ctx context.Context, userId uuid.UUID) error
}

type Password interface {
	RequestReset(ctx context.Context, email, username *string, resetLinkPattern string) error
	Reset(ctx context.Context, userId uuid.UUID, resetCode, newPassword string) error
	Change(ctx context.Context, userId uuid.UUID, oldPassword, newPassword string) error
}

type Username interface {
	Get(ctx context.Context, userIds []uuid.UUID) (map[uuid.UUID]string, error)
	CheckAvailability(ctx context.Context, username string) (bool, error)
	Set(ctx context.Context, userId uuid.UUID, username string) error
}

type ProfileDeletion interface {
	GetInfo(ctx context.Context, userId uuid.UUID) (*time.Time, bool)
	Request(ctx context.Context, userId uuid.UUID, credentials entity.Reauthentication, deleteSharedData bool, redirect string) (entity.DeleteProfileRequest, error)
	Update(ctx context.Context, userId uuid.UUID, deleteSharedData bool) (entity.DeleteProfileRequest, error)
	ExecuteAll()
	Execute(ctx context.Context, request entity.DeleteProfileRequest) error
	Cancel(ctx context.Context, userId uuid.UUID) error
}

func New(
	ctx context.Context,
	cfg *config.Config,
	repo repository.Data,
	grpc *grpc.Repository,
	mq repository.MessageQueue,
) (*Service, error) {
	ipInfoProvider := ip.NewFreeIpApiProvider()

	mailService, err := mail.NewService(ipInfoProvider, cfg)
	if err != nil {
		return nil, err
	}

	hashManager := hash.NewBcryptManager(*cfg.Auth.SaltCost)

	var tokenManager *tokens.Manager = nil
	if len(*cfg.Auth.AccessTokenSigningKey) > 0 {
		tokenManager, err = tokens.NewManagerByRawKey([]byte(*cfg.Auth.AccessTokenSigningKey))
		if err != nil {
			return nil, err
		}
	} else {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		tokenManager = tokens.NewManagerByKey(key)
	}

	googleProvider := google.NewOAuthProvider(
		*cfg.OAuth.Google.ClientId,
		*cfg.OAuth.Google.ClientSecret,
		*cfg.OAuth.State,
		[]string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"openid",
		},
	)
	vkProvider := vk.NewOAuthProvider(
		*cfg.OAuth.Vk.ClientId,
		*cfg.OAuth.Vk.ClientSecret,
		strconv.Itoa(oauthService.VkScope),
		*cfg.OAuth.State,
	)
	googleProvider.StateStore = repo
	vkProvider.StateStore = repo
	oauthProviders := oauth.Providers{
		Google: *googleProvider,
		Vk:     *vkProvider,
	}

	var firebaseClient *firebase.Client = nil
	if len(*cfg.Auth.Firebase.Credentials) > 0 && len(*cfg.Auth.Firebase.GoogleApiKey) > 0 {
		credentials := []byte(*cfg.Auth.Firebase.Credentials)
		if client, err := firebase.NewClient(credentials, *cfg.Auth.Firebase.GoogleApiKey); err == nil {
			firebaseClient = client
			authlog.Default.FirebaseClientInitialized(ctx)
		}
	}

	email := emailService.New(repo, reauthentication.New(repo, oauthProviders, hashManager), mailService)
	return &Service{
		Email:           email,
		Session:         session.NewService(repo, grpc, mq, *mailService, oauthProviders, hashManager, *tokenManager, ipInfoProvider, firebaseClient, cfg.Auth, email),
		OAuth:           oauthService.NewService(repo, oauthProviders),
		Password:        password.NewService(repo, *mailService, hashManager, cfg.Auth),
		Username:        username.NewService(repo, *mailService),
		ProfileDeletion: profile_deletion.NewService(repo, mq, mailService, hashManager, reauthentication.New(repo, oauthProviders, hashManager)),
	}, nil
}
