package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

const (
	usersTable                 = "users"
	activationCodesTable       = "activation_codes"
	sessionsTable              = "sessions"
	oauthTable                 = "oauth"
	firebaseTable              = "firebase"
	passwordResetsTable        = "password_resets"
	deleteProfileRequestsTable = "delete_profile_requests"
	outboxTable                = "outbox"

	errUniqueViolation = "23505"
)

type Repository struct {
	db                  *sqlx.DB
	profileDeleteOffset time.Duration
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

func NewRepository(db *sqlx.DB, profileDeleteOffset time.Duration) *Repository {
	return &Repository{
		db:                  db,
		profileDeleteOffset: profileDeleteOffset,
	}
}

func errorWithTransactionRollback(tx *sql.Tx, err error) error {
	_ = tx.Rollback()
	return err
}

func commitTransaction(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		log.Error("unable to commit transaction: ", err)
		_ = tx.Rollback()
		return fail.GrpcUnknown
	}
	return nil
}

func isUniqueViolationError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == errUniqueViolation
	}
	return false
}
