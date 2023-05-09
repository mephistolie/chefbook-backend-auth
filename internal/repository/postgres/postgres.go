package postgres

import (
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
)

const (
	usersTable           = "users"
	activationCodesTable = "activation_codes"
	sessionsTable        = "sessions"
	oauthTable           = "oauth"
	firebaseTable        = "firebase"
	passwordResetsTable  = "password_resets"
	outboxTable          = "outbox"
)

type Repository struct {
	db *sqlx.DB
}

func Connect(cfg config.Database) (*sqlx.DB, error) {
	db, err := sqlx.Connect("pgx",
		fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=require",
			*cfg.Host, *cfg.Port, *cfg.User, *cfg.DBName, *cfg.Password))
	if err != nil {
		return nil, err
	}

	return db, nil
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}
