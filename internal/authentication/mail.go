package authentication

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// mailRequest mirrors the versioned mail.send.v1 contract. Keeping the wire DTO
// local avoids a deployment-time cross-service filesystem/module dependency.
type mailRequest struct {
	Username            string     `json:"username,omitempty"`
	Timestamp           *time.Time `json:"timestamp,omitempty"`
	DeleteSharedData    bool       `json:"deleteSharedData,omitempty"`
	Client              string     `json:"client,omitempty"`
	To                  string     `json:"to"`
	Template            string     `json:"template"`
	Code                string     `json:"code,omitempty"`
	URL                 string     `json:"url,omitempty"`
	ExpirationTimestamp time.Time  `json:"expirationTimestamp"`
}
type OutboxMail struct{}

func (OutboxMail) QueueCode(ctx context.Context, tx *sql.Tx, to, code string, expiry time.Time) error {
	return queueMail(ctx, tx, mailRequest{To: to, Template: "registration_code", Code: code, ExpirationTimestamp: expiry})
}
func queueMail(ctx context.Context, tx *sql.Tx, m mailRequest) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox(message_id,exchange,type,body) VALUES($1,'mail','mail.send.v1',$2)`, uuid.New(), body)
	return err
}
func confirmationURL(base, token string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", ErrUnavailable
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (e *Engine) StartPasswordReset(ctx context.Context, email, baseURL string) error {
	if _, err := confirmationURL(baseURL, "configuration-check"); err != nil {
		return err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var account uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT account_id FROM accounts WHERE email=$1 AND blocking_timestamp IS NULL FOR UPDATE`, email).Scan(&account)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	link, err := confirmationURL(baseURL, token)
	if err != nil {
		return err
	}
	expiry := e.Now().Add(30 * time.Minute)
	_, err = tx.ExecContext(ctx, `INSERT INTO password_reset_requests(account_id,token_hash,expiration_timestamp) VALUES($1,$2,$3) ON CONFLICT(account_id) DO UPDATE SET token_hash=EXCLUDED.token_hash,creation_timestamp=now(),expiration_timestamp=EXCLUDED.expiration_timestamp`, account, e.Secrets.Hash("reset", "", token), expiry)
	if err != nil {
		return err
	}
	if err = queueMail(ctx, tx, mailRequest{To: email, Template: "password_reset", URL: link, ExpirationTimestamp: expiry}); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) ConfirmPasswordReset(ctx context.Context, token, password string) error {
	if len(password) < 8 || len(password) > 72 {
		return ErrInvalid
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), e.BcryptCost)
	if err != nil {
		return err
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var account uuid.UUID
	err = tx.QueryRowContext(ctx, `DELETE FROM password_reset_requests WHERE token_hash=$1 AND expiration_timestamp>$2 RETURNING account_id`, e.Secrets.Hash("reset", "", token), e.Now()).Scan(&account)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalid
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE accounts SET password_hash=$2,password_change_timestamp=$3 WHERE account_id=$1`, account, string(hash), e.Now())
	if err != nil {
		return err
	}
	if err = e.invalidate(ctx, tx, account); err != nil {
		return err
	}
	if err = e.notifyAccount(ctx, tx, account, mailRequest{Template: "password_changed"}); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE account_id=$1`, account)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) ChangeEmail(ctx context.Context, who Principal, grant, email, baseURL string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email {
		return ErrInvalid
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "emailChange", who); err != nil {
		return err
	}
	var old string
	err = tx.QueryRowContext(ctx, `SELECT email FROM accounts WHERE account_id=$1 FOR UPDATE`, who.AccountID).Scan(&old)
	if err != nil {
		return err
	}
	if old == email {
		return ErrConflict
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	expiry := e.Now().Add(30 * time.Minute)
	link, err := confirmationURL(baseURL, token)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO email_change_requests(account_id,previous_email,email,stage,token_hash,expiration_timestamp) VALUES($1,$2,$3,'awaiting_previous_email',$4,$5)`, who.AccountID, old, email, e.Secrets.Hash("email-change", "", token), expiry)
	if err != nil {
		return conflict(err)
	}
	if err = queueMail(ctx, tx, mailRequest{To: old, Template: "email_change_previous", URL: link, ExpirationTimestamp: expiry}); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) ConfirmEmail(ctx context.Context, token, baseURL string) (string, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var account uuid.UUID
	var old, email, stage string
	err = tx.QueryRowContext(ctx, `SELECT account_id,previous_email,email,stage FROM email_change_requests WHERE token_hash=$1 AND expiration_timestamp>$2 FOR UPDATE`, e.Secrets.Hash("email-change", "", token), e.Now()).Scan(&account, &old, &email, &stage)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalid
	}
	if err != nil {
		return "", err
	}
	result := "changed"
	if stage == "awaiting_previous_email" {
		next, err := randomToken()
		if err != nil {
			return "", err
		}
		expiry := e.Now().Add(30 * time.Minute)
		link, err := confirmationURL(baseURL, next)
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, `UPDATE email_change_requests SET stage='awaiting_new_email',token_hash=$2,expiration_timestamp=$3 WHERE account_id=$1`, account, e.Secrets.Hash("email-change", "", next), expiry)
		if err != nil {
			return "", err
		}
		if err = queueMail(ctx, tx, mailRequest{To: email, Template: "email_change_new", URL: link, ExpirationTimestamp: expiry}); err != nil {
			return "", err
		}
		result = "pendingNewEmail"
	} else {
		res, err := tx.ExecContext(ctx, `UPDATE accounts SET email=$2,email_verification_timestamp=$3 WHERE account_id=$1 AND email=$4`, account, email, e.Now(), old)
		if err != nil {
			return "", conflict(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return "", err
		}
		if n != 1 {
			return "", ErrConflict
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM email_change_requests WHERE account_id=$1`, account); err != nil {
			return "", err
		}
		if err = e.invalidate(ctx, tx, account); err != nil {
			return "", err
		}
	}
	return result, tx.Commit()
}

func (e *Engine) notifyAccount(ctx context.Context, tx *sql.Tx, account uuid.UUID, m mailRequest) error {
	if err := tx.QueryRowContext(ctx, `SELECT email FROM accounts WHERE account_id=$1`, account).Scan(&m.To); err != nil {
		return err
	}
	if m.ExpirationTimestamp.IsZero() {
		m.ExpirationTimestamp = e.Now().Add(24 * time.Hour)
	}
	return queueMail(ctx, tx, m)
}
