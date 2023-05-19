package config

import (
	"errors"
	"github.com/mephistolie/chefbook-backend-common/log"
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

	Auth     Auth
	OAuth    OAuth
	Database Database
	Amqp     Amqp
	Smtp     Smtp
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

type Database struct {
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
	log.Infof("AUTH SERVICE CONFIGURATION\n"+
		"Environment: %v\n"+
		"Port: %v\n"+
		"Logs path: %v\n\n"+
		"Salt cost: %v\n"+
		"Access token TTL: %v\n"+
		"Refresh token TTL: %v\n"+
		"Password reset code TTL: %v\n\n"+
		"Database host: %v\n"+
		"Database port: %v\n"+
		"Database name: %v\n\n"+
		"MQ host: %v\n"+
		"MQ port: %v\n"+
		"MQ vhost: %v\n\n"+
		"SMTP host: %v\n"+
		"SMTP port: %v\n\n"+
		"OAuth state: %v\n"+
		"Google Client ID: %v\n"+
		"VK Client ID: %v\n",
		*c.Environment, *c.Port, *c.LogsPath,
		*c.Auth.SaltCost, *c.Auth.Ttl.AccessToken, *c.Auth.Ttl.RefreshToken, *c.Auth.Ttl.PasswordResetCode,
		*c.Database.Host, *c.Database.Port, *c.Database.DBName,
		*c.Amqp.Host, *c.Amqp.Port, *c.Amqp.VHost,
		*c.Smtp.Host, *c.Smtp.Port,
		*c.OAuth.State,
		*c.OAuth.Google.ClientId,
		*c.OAuth.Vk.ClientId,
	)
}
