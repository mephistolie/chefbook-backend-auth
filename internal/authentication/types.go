// Package authentication implements the server-owned multi-step authentication state
// machine against schema/initial.sql. The legacy service must not use this schema.
package authentication

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/pkg/passkey"
)

var (
	ErrAccountExists = errors.New("account_exists")
	ErrNotFound      = errors.New("not_found")
	ErrSession       = errors.New("invalid_session")
	ErrInvalid       = errors.New("invalid_request")
	ErrUnauthorized  = errors.New("invalid_flow_token")
	ErrCredentials   = errors.New("invalid_credentials")
	ErrConflict      = errors.New("conflict")
	ErrForbidden     = errors.New("insufficient_authentication")
	ErrUnavailable   = errors.New("method_unavailable")
	ErrAttempts      = errors.New("too_many_attempts")
)

type Purpose struct {
	Type string `json:"type"`
}
type Next struct {
	Methods []string `json:"methods"`
}
type Process struct {
	ID                              uuid.UUID   `json:"id"`
	Purpose                         Purpose     `json:"purpose"`
	Status                          string      `json:"status"`
	ExpirationTimestamp             time.Time   `json:"expirationTimestamp"`
	Next                            Next        `json:"next"`
	Steps                           []Challenge `json:"steps"`
	FlowToken                       string      `json:"flowToken,omitempty"`
	ConfirmationToken               string      `json:"confirmationToken,omitempty"`
	ConfirmationExpirationTimestamp *time.Time  `json:"confirmationExpirationTimestamp,omitempty"`
	accountID                       uuid.NullUUID
	sessionID                       sql.NullInt64
	failures                        int
}
type StartRequest struct {
	Purpose Purpose
}
type Principal struct {
	AccountID uuid.UUID
	SessionID int64
}
type Challenge struct {
	URL, Nonce          string
	PublicKey           []byte    `json:"-"`
	ID                  uuid.UUID `json:"id"`
	Method              string    `json:"method"`
	Status              string    `json:"status"`
	ExpirationTimestamp time.Time `json:"expirationTimestamp"`
}
type Proof struct {
	Email, Name                   string
	IDToken, State                string
	Method, Login, Password, Code string
	Credential                    []byte
}
type Attempt struct {
	Challenge      Challenge `json:"challenge"`
	Authentication Process   `json:"authentication"`
}

// MailSink writes into the SAME transaction as its triggering state transition.
// It must never send SMTP while database locks are held.
type MailSink interface {
	QueueCode(context.Context, *sql.Tx, string, string, time.Time) error
}
type Engine struct {
	dummyOnce                                 sync.Once
	dummyPasswordHash                         []byte
	dummyPasswordError                        error
	activationAttempts                        activationLimiter
	DB                                        *sql.DB
	Providers                                 map[string]Provider
	OAuthRedirects                            []string
	Passkeys                                  *passkey.Verifier
	Secrets                                   Secrets
	Mail                                      MailSink
	Now                                       func() time.Time
	BcryptCost                                int
	FlowTTL, ChallengeTTL, GrantTTL, ReuseTTL time.Duration
	MaxAttempts                               int
}

func New(db *sql.DB, secrets Secrets, mail MailSink) *Engine {
	return &Engine{DB: db, Secrets: secrets, Mail: mail, Now: time.Now, BcryptCost: 12, FlowTTL: 15 * time.Minute, ChallengeTTL: 5 * time.Minute, GrantTTL: 2 * time.Minute, ReuseTTL: 5 * time.Minute, MaxAttempts: 10}
}
func validPurpose(p string) bool {
	switch p {
	case "signIn", "signUp", "passwordChange", "emailChange", "accountDeletion", "totpEnrollment", "totpRemoval", "passkeyEnrollment", "passkeyRemoval", "backupCodesRotation", "identityLink", "identityUnlink":
		return true
	}
	return false
}
func sensitive(p string) bool { return p != "signIn" && p != "signUp" }
