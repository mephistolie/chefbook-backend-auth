package session

import (
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/repository/grpc"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	"github.com/mephistolie/chefbook-backend-auth/pkg/ip"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth"
	"github.com/mephistolie/chefbook-backend-common/firebase"
	"github.com/mephistolie/chefbook-backend-common/hash"
	"github.com/mephistolie/chefbook-backend-common/tokens"
	"time"
)

const (
	activationCodeLength = 6
	maxSessionsCount     = 5
)

type Service struct {
	repo                 repository.Data
	grpc                 *grpc.Repository
	mq                   repository.MessageQueue
	mail                 mail.Service
	oauthProviders       oauth.Providers
	hashManager          hash.Manager
	tokenManager         tokens.Manager
	firebase             *firebase.Client
	ipInfoProvider       ip.InfoProvider
	accessTokenTtl       time.Duration
	refreshTokenTtl      time.Duration
	resetPasswordCodeTTL time.Duration
}

func NewService(
	repo repository.Data,
	grpc *grpc.Repository,
	mq repository.MessageQueue,
	mailService mail.Service,
	oauthProviders oauth.Providers,
	hashManager hash.Manager,
	tokenManager tokens.Manager,
	ipInfoProvider ip.InfoProvider,
	firebase *firebase.Client,
	cfg config.Auth,
) *Service {
	return &Service{
		repo:                 repo,
		grpc:                 grpc,
		mq:                   mq,
		mail:                 mailService,
		oauthProviders:       oauthProviders,
		hashManager:          hashManager,
		tokenManager:         tokenManager,
		ipInfoProvider:       ipInfoProvider,
		firebase:             firebase,
		accessTokenTtl:       *cfg.Ttl.AccessToken,
		refreshTokenTtl:      *cfg.Ttl.RefreshToken,
		resetPasswordCodeTTL: *cfg.Ttl.PasswordResetCode,
	}
}
