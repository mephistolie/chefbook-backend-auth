package config

import (
	"errors"
	"github.com/mephistolie/chefbook-backend-common/log"
	"time"
)

const (
	EnvDebug = "debug"
	EnvProd  = "production"
)

type Config struct {
	Environment *string
	Port        *int
	LogsPath    *string

	Auth     Auth
	OAuth    OAuth
	Database Database
	Smtp     Smtp
}

type Auth struct {
	SaltCost                  *int
	AccessTokenPrivateKeyPath *string
	AccessTokenPublicKeyPath  *string
	Ttl                       Ttl
	Firebase                  Firebase
}

type Ttl struct {
	AccessToken       *time.Duration
	RefreshToken      *time.Duration
	ResetPasswordCode *time.Duration
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

type Database struct {
	Host     *string
	Port     *int
	User     *string
	Password *string
	DBName   *string
}

type Smtp struct {
	Host         *string
	Port         *int
	Sender       *string
	Password     *string
	SendAttempts *int
}

func (c Config) Validate() error {
	if *c.Environment != EnvProd {
		*c.Environment = EnvDebug
	}
	if *c.Auth.AccessTokenPrivateKeyPath == "" {
		return errors.New("access tokens signing private key path is empty")
	}
	if *c.Auth.AccessTokenPublicKeyPath == "" {
		return errors.New("access tokens signing public key path is empty")
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
	log.Infof("SERVICE CONFIGURATION\n"+
		"Environment: %v\n"+
		"Port: %v\n"+
		"Logs path: %v\n\n"+
		"Salt cost: %v\n"+
		"Access tokens TTL: %v\n"+
		"Refresh tokens TTL: %v\n"+
		"Password reset code TTL: %v\n\n"+
		"Database host: %v\n"+
		"Database port: %v\n"+
		"Database name: %v\n\n"+
		"SMTP host: %v\n"+
		"SMTP port: %v\n\n"+
		"OAuth state: %v\n"+
		"Google Client ID: %v\n"+
		"VK Client ID: %v\n",
		*c.Environment, *c.Port, *c.LogsPath,
		*c.Auth.SaltCost, *c.Auth.Ttl.AccessToken, *c.Auth.Ttl.RefreshToken, *c.Auth.Ttl.ResetPasswordCode,
		*c.Database.Host, *c.Database.Port, *c.Database.DBName,
		*c.Smtp.Host, *c.Smtp.Port,
		*c.OAuth.State,
		*c.OAuth.Google.ClientId,
		*c.OAuth.Vk.ClientId,
	)
}
