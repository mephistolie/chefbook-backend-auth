package service

import (
	"fmt"
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
	SignUp(credentials entity.SignUpCredentials) (uuid.UUID, bool, error)
	ActivateProfile(userId uuid.UUID, code string) error
	SignIn(credentials entity.SignInCredentials, client entity.ClientData) (entity.Tokens, error)
	SignInGoogle(credentials entity.OAuthCredentials, client entity.ClientData) (entity.Tokens, error)
	SignInVk(credentials entity.OAuthCredentials, client entity.ClientData) (entity.Tokens, error)
	GetAccessTokenPublicKey() []byte
	Refresh(refreshToken, ip, userAgent string) (entity.Tokens, error)
	SignOut(refreshToken string) error
	GetAuthInfo(identifiers entity.UserIdentifiers) (entity.AuthInfo, error)
	DeleteProfile(userId uuid.UUID, password string) error
	GetAll(userId uuid.UUID) []entity.SessionInfo
	DeleteMultiple(userId uuid.UUID, sessionIds []int64)
}

type OAuth interface {
	GenerateGoogleLink() string
	ConnectGoogle(userId uuid.UUID, code, state string) error
	DeleteGoogleConnection(userId uuid.UUID) error
	GenerateVkLink(display, responseType string) (string, error)
	ConnectVk(userId uuid.UUID, code, state string) error
	DeleteVkConnection(userId uuid.UUID) error
}

type Password interface {
	RequestReset(email, nickname *string) error
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

	mailService, err := mail.NewService(ipInfoProvider, cfg)
	if err != nil {
		return nil, err
	}

	hashManager := hash.NewBcryptManager(*cfg.Auth.SaltCost)

	tokenManager, err := tokens.NewManager(*cfg.Auth.AccessTokenPrivateKeyPath, *cfg.Auth.AccessTokenPublicKeyPath)
	if err != nil {
		return nil, err
	}

	googleProvider := google.NewOAuthProvider(
		*cfg.OAuth.Google.ClientId,
		*cfg.OAuth.Google.ClientSecret,
		fmt.Sprintf("%s/%s", *cfg.FrontendUrl, *cfg.OAuth.Google.RedirectUri),
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
		fmt.Sprintf("%s/%s", *cfg.FrontendUrl, *cfg.OAuth.Vk.RedirectUri),
		strconv.Itoa(oauthService.VkScope),
		*cfg.OAuth.State,
	)
	oauthProviders := oauth.Providers{
		Google: *googleProvider,
		Vk:     *vkProvider,
	}

	var firebaseClient *firebase.Client = nil
	if len(*cfg.Auth.Firebase.GoogleApiKey) > 0 {
		if client, err := firebase.NewClient(*cfg.Auth.Firebase.ConfigPath, *cfg.Auth.Firebase.GoogleApiKey); err == nil {
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
