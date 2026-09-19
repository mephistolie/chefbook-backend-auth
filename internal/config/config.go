package config

import (
	"context"
	"errors"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"time"
)

const (
	EnvDev  = "develop"
	EnvProd = "production"
)

type Config struct {
	Environment *string
	Port        *int
	LogsPath    *string

	Security        Security
	Auth            Auth
	OAuth           OAuth
	ProfileDeletion ProfileDeletion

	SubscriptionService Service

	Database Database
	Amqp     Amqp
	Smtp     Smtp
}

type Security struct {
	HMACKey, EncryptionKey                           *string
	RPID, Origins, OpaqueOrigins                     *string
	OAuthRedirects, PasswordResetURL, EmailChangeURL *string
}

type Auth struct {
	SaltCost              *int
	AccessTokenSigningKey *string
	Ttl                   Ttl
	Firebase              Firebase
}

type Ttl struct {
	AccessToken       *time.Duration
	RefreshToken      *time.Duration
	PasswordResetCode *time.Duration
}

type Firebase struct {
	Credentials  *string
	GoogleApiKey *string
}

type OAuth struct {
	State  *string
	Google Google
	Vk     Vk
}

type Google struct {
	ClientId     *string
	ClientSecret *string
}

type Vk struct {
	ClientId     *string
	ClientSecret *string
}

type ProfileDeletion struct {
	Offset        *time.Duration
	CheckInterval *time.Duration
}

type Service struct {
	Addr *string
}

type Database struct {
	SSLMode  *string
	Host     *string
	Port     *int
	User     *string
	Password *string
	DBName   *string
}

type Amqp struct {
	Host     *string
	Port     *int
	User     *string
	Password *string
	VHost    *string
}

type Smtp struct {
	Username     *string
	Host         *string
	Port         *int
	Email        *string
	Password     *string
	SendAttempts *int
}

func (c Config) Validate() error {
	if *c.Environment != EnvProd {
		*c.Environment = EnvDev
	}

	if *c.Database.Host == "" {
		return errors.New("database host is empty")
	}
	if *c.Database.DBName == "" {
		return errors.New("database name is empty")
	}
	if *c.Database.User == "" {
		return errors.New("database username is empty")
	}
	if *c.Database.Password == "" {
		return errors.New("database user password is empty")
	}

	return nil
}

func (c Config) Print() {
	authlog.Default.ConfigLoaded(context.Background())
}
