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
	FrontendUrl *string
	BackendUrl  *string
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
	ConfigPath   *string
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
	RedirectUri  *string
}

type Vk struct {
	ClientId     *string
	ClientSecret *string
	RedirectUri  *string
}

type Database struct {
	Host     *string
	Port     *int
	User     *string
	Password *string
	DBName   *string
}

type Smtp struct {
	Host                       *string
	Port                       *int
	Sender                     *string
	Password                   *string
	ProfileActivationRouteTmpl *string
	PasswordResetRouteTmpl     *string
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
	log.Info("SERVICE CONFIGURATION\n"+
		"Environment: %v\n"+
		"Port: %v\n\n"+
		"Frontend URL: %v\n"+
		"Backend URL: %v\n"+
		"Logs dir: %v\n\n"+
		"Activate Profile Route: %v\n"+
		"Password Reset Route: %v\n\n"+
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
		"Google Redirect Route: %v\n"+
		"VK Client ID: %v\n"+
		"VK Redirect Route: %v\n\n",
		*c.Environment, *c.Port,
		*c.FrontendUrl, *c.BackendUrl,
		*c.LogsPath,
		*c.Smtp.ProfileActivationRouteTmpl, *c.Smtp.PasswordResetRouteTmpl,
		*c.Auth.SaltCost, *c.Auth.Ttl.AccessToken, *c.Auth.Ttl.RefreshToken, *c.Auth.Ttl.ResetPasswordCode,
		*c.Database.Host, *c.Database.Port, *c.Database.DBName,
		*c.Smtp.Host, *c.Smtp.Port,
		*c.OAuth.State,
		*c.OAuth.Google.ClientId, *c.OAuth.Google.RedirectUri,
		*c.OAuth.Vk.ClientId, *c.OAuth.Vk.RedirectUri,
	)
}
