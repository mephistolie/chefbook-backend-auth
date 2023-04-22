package service

import (
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/nickname"
	oauthService "github.com/mephistolie/chefbook-backend-auth/internal/service/oauth"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/password"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/session"
	"github.com/mephistolie/chefbook-backend-auth/pkg/ip"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/google"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/vk"
	firebase "github.com/mephistolie/chefbook-backend-common/firebase"
	"github.com/mephistolie/chefbook-backend-common/hash"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/tokens"
	"strconv"
)

type Service struct {
	Session  Session
	OAuth    OAuth
	Password Password
	Nickname Nickname
}

type Session interface {
	SignUp(credentials entity.SignUpCredentials, activationLinkPattern string) (uuid.UUID, bool, error)
	ActivateProfile(userId uuid.UUID, code string) error
	SignIn(credentials entity.SignInCredentials, client entity.ClientData) (entity.Tokens, error)
	SignInGoogle(credentials entity.OAuthCredentials, client entity.ClientData, redirectUrl string) (entity.Tokens, error)
	SignInVk(credentials entity.OAuthCredentials, client entity.ClientData, redirectUri string) (entity.Tokens, error)
	GetAccessTokenPublicKey() []byte
	Refresh(refreshToken, ip, userAgent string) (entity.Tokens, error)
	SignOut(refreshToken string) error
	GetAuthInfo(identifiers entity.UserIdentifiers) (entity.AuthInfo, error)
	DeleteProfile(userId uuid.UUID, password string) error
	GetAll(userId uuid.UUID) []entity.SessionInfo
	DeleteMultiple(userId uuid.UUID, sessionIds []int64)
}

type OAuth interface {
	GenerateGoogleLink(redirectUrl string) string
	ConnectGoogle(userId uuid.UUID, code, state, redirectUri string) error
	DeleteGoogleConnection(userId uuid.UUID) error
	GenerateVkLink(display, responseType, redirectUrl string) (string, error)
	ConnectVk(userId uuid.UUID, code, state, redirectUri string) error
	DeleteVkConnection(userId uuid.UUID) error
}

type Password interface {
	RequestReset(email, nickname *string, resetLinkPattern string) error
	Reset(userId uuid.UUID, resetCode, newPassword string) error
	Change(userId uuid.UUID, oldPassword, newPassword string) error
}

type Nickname interface {
	CheckAvailability(nickname string) (bool, error)
	Set(userId uuid.UUID, nickname string) error
}

func New(
	cfg *config.Config,
	repo repository.Auth,
) (*Service, error) {
	ipInfoProvider := ip.NewFreeIpApiProvider()

	mailService, err := mail.NewService(ipInfoProvider, cfg.Smtp)
	if err != nil {
		return nil, err
	}

	hashManager := hash.NewBcryptManager(*cfg.Auth.SaltCost)

	tokenManager, err := tokens.NewManagerByKey([]byte(*cfg.Auth.AccessTokenSigningKey))
	if err != nil {
		return nil, err
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
	oauthProviders := oauth.Providers{
		Google: *googleProvider,
		Vk:     *vkProvider,
	}

	var firebaseClient *firebase.Client = nil
	if len(*cfg.Auth.Firebase.GoogleApiKey) > 0 {
		credentials := []byte(*cfg.Auth.Firebase.Credentials)
		if client, err := firebase.NewClient(credentials, *cfg.Auth.Firebase.GoogleApiKey); err == nil {
			firebaseClient = client
			log.Info("Firebase client initialized")
		}
	}

	return &Service{
		Session:  session.NewService(repo, *mailService, oauthProviders, hashManager, *tokenManager, ipInfoProvider, firebaseClient, cfg.Auth),
		OAuth:    oauthService.NewService(repo, oauthProviders),
		Password: password.NewService(repo, *mailService, hashManager, cfg.Auth),
		Nickname: nickname.NewService(repo, *mailService),
	}, nil
}
