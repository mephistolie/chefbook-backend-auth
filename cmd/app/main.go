package main

import (
	"flag"
	"github.com/mephistolie/chefbook-backend-auth/internal/app"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-common/random"
	"github.com/peterbourgon/ff/v3"
	"os"
	"time"
)

func main() {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	cfg := config.Config{
		Environment: fs.String("environment", "debug", "service environment"),
		Port:        fs.Int("port", 8080, "service port"),
		LogsPath:    fs.String("logs-path", "logs/all.log", "logs file path"),

		Auth: config.Auth{
			SaltCost:              fs.Int("salt-cost", 10, "hash data salt cost"),
			AccessTokenSigningKey: fs.String("access-token-signing-key", "", "access token signing key"),
			Ttl: config.Ttl{
				AccessToken:       fs.Duration("access-token-ttl", 20*time.Minute, "access tokens time to live"),
				RefreshToken:      fs.Duration("refresh-token-ttl", 24*time.Hour*30, "refresh tokens time to live"),
				PasswordResetCode: fs.Duration("password-reset-code-ttl", 24*time.Hour, "reset password code time to live"),
			},
			Firebase: config.Firebase{
				Credentials:  fs.String("firebase-credentials", "", "Firebase credentials JSON"),
				GoogleApiKey: fs.String("firebase-api-key", "", "Google API key for Firebase client"),
			},
		},

		OAuth: config.OAuth{
			State: fs.String("oauth-state", random.DigitString(10), "state param for OAuth queries"),
			Google: config.Google{
				ClientId:     fs.String("google-client-id", "", "Google API client ID"),
				ClientSecret: fs.String("google-client-secret", "", "Google API client secret"),
			},
			Vk: config.Vk{
				ClientId:     fs.String("vk-client-id", "", "VK API client ID"),
				ClientSecret: fs.String("vk-client-secret", "", "VK API client secret"),
			},
		},

		Database: config.Database{
			Host:     fs.String("db-host", "localhost", "database host"),
			Port:     fs.Int("db-port", 5432, "database port"),
			User:     fs.String("db-user", "", "database user name"),
			Password: fs.String("db-password", "", "database user password"),
			DBName:   fs.String("db-name", "", "service database name"),
		},

		Smtp: config.Smtp{
			Host:         fs.String("smtp-host", "", "SMTP host; leave empty to disable emails"),
			Port:         fs.Int("smtp-port", 465, "SMTP port"),
			Email:        fs.String("smtp-email", "", "SMTP sender email"),
			Password:     fs.String("smtp-password", "", "SMTP sender password"),
			SendAttempts: fs.Int("smtp-attempts", 3, "SMTP email sending attempts"),
		},
	}
	if err := ff.Parse(fs, os.Args[1:], ff.WithEnvVars()); err != nil {
		panic(err)
	}

	err := cfg.Validate()
	if err != nil {
		panic(err)
	}

	app.Run(&cfg)
}
