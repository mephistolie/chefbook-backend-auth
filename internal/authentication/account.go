package authentication

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/assets"
	"golang.org/x/crypto/bcrypt"
)

func (e *Engine) invalidate(ctx context.Context, tx *sql.Tx, account uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `UPDATE authentications SET invalidation_timestamp=$2,confirmation_token_hash=NULL,confirmation_expiration_timestamp=NULL WHERE account_id=$1 AND invalidation_timestamp IS NULL`, account, e.Now())
	return err
}
func (e *Engine) SetPassword(ctx context.Context, who Principal, grant, password string) error {
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
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return err
	}
	var existing sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT password_hash FROM accounts WHERE account_id=$1 FOR UPDATE`, who.AccountID).Scan(&existing)
	if err != nil {
		return err
	}
	if existing.Valid {
		if _, err = e.ConsumeGrant(ctx, tx, grant, "passwordChange", who); err != nil {
			return err
		}
		if bcrypt.CompareHashAndPassword([]byte(existing.String), []byte(password)) == nil {
			return tx.Commit()
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE accounts SET password_hash=$2,password_change_timestamp=$3 WHERE account_id=$1`, who.AccountID, string(hash), e.Now())
	if err != nil {
		return err
	}
	if err = e.invalidate(ctx, tx, who.AccountID); err != nil {
		return err
	}
	if err = e.notifyAccount(ctx, tx, who.AccountID, mailRequest{Template: "password_changed"}); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE account_id=$1 AND session_id<>$2`, who.AccountID, who.SessionID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) UsernameAvailable(ctx context.Context, username string) (bool, error) {
	username = normalizeUsername(username)
	if !validUsername(username) {
		return false, nil
	}
	var found bool
	err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE username=$1)`, strings.ToLower(username)).Scan(&found)
	return !found, err
}
func (e *Engine) SetUsername(ctx context.Context, who Principal, username string) error {
	username = normalizeUsername(username)
	if !validUsername(username) {
		return ErrInvalid
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return err
	}
	var email string
	err = tx.QueryRowContext(ctx, `UPDATE accounts SET username=$2 WHERE account_id=$1 AND username IS DISTINCT FROM $2 RETURNING email`, who.AccountID, username).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return conflict(err)
	}
	if err = e.notifyAccount(ctx, tx, who.AccountID, mailRequest{Template: "username_changed", Username: username}); err != nil {
		return err
	}
	return tx.Commit()
}
func conflict(err error) error {
	var state interface{ SQLState() string }
	if errors.As(err, &state) && state.SQLState() == "23505" {
		return ErrConflict
	}
	return err
}

type Deletion struct {
	DeletionTimestamp time.Time
	DeleteSharedData  bool
}

func (e *Engine) RequestDeletion(ctx context.Context, who Principal, grant string, shared bool, delay time.Duration) (Deletion, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Deletion{}, err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "accountDeletion", who); err != nil {
		return Deletion{}, err
	}
	var d Deletion
	err = tx.QueryRowContext(ctx, `INSERT INTO account_deletion_requests(account_id,delete_shared_data,deletion_timestamp) VALUES($1,$2,$3) ON CONFLICT(account_id) DO UPDATE SET delete_shared_data=EXCLUDED.delete_shared_data WHERE account_deletion_requests.deletion_timestamp>$4 RETURNING deletion_timestamp,delete_shared_data`, who.AccountID, shared, e.Now().Add(delay), e.Now()).Scan(&d.DeletionTimestamp, &d.DeleteSharedData)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrConflict
	}
	if err != nil {
		return d, err
	}
	if err = e.notifyAccount(ctx, tx, who.AccountID, mailRequest{Template: "account_deletion_requested", Timestamp: &d.DeletionTimestamp, DeleteSharedData: shared}); err != nil {
		return d, err
	}
	err = tx.Commit()
	return d, err
}
func (e *Engine) PatchDeletion(ctx context.Context, who Principal, shared bool) (Deletion, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Deletion{}, err
	}
	defer tx.Rollback()
	if err = e.checkRecoveryPrincipal(ctx, tx, who); err != nil {
		return Deletion{}, err
	}
	var d Deletion
	err = tx.QueryRowContext(ctx, `UPDATE account_deletion_requests SET delete_shared_data=$2 WHERE account_id=$1 AND deletion_timestamp>$3 RETURNING deletion_timestamp,delete_shared_data`, who.AccountID, shared, e.Now()).Scan(&d.DeletionTimestamp, &d.DeleteSharedData)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		checkErr := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account_deletion_requests WHERE account_id=$1)`, who.AccountID).Scan(&exists)
		if checkErr != nil {
			return d, checkErr
		}
		if exists {
			return d, ErrConflict
		}
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	err = tx.Commit()
	return d, err
}
func (e *Engine) CancelDeletion(ctx context.Context, who Principal) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = e.checkRecoveryPrincipal(ctx, tx, who); err != nil {
		return err
	}
	var deadline time.Time
	err = tx.QueryRowContext(ctx, `SELECT deletion_timestamp FROM account_deletion_requests WHERE account_id=$1 FOR UPDATE`, who.AccountID).Scan(&deadline)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if !deadline.After(e.Now()) {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM account_deletion_requests WHERE account_id=$1`, who.AccountID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDueAccount performs one deletion atomically with its lifecycle outbox event.
func (e *Engine) DeleteDueAccount(ctx context.Context) (bool, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var account uuid.UUID
	var shared bool
	err = tx.QueryRowContext(ctx, `SELECT a.account_id,d.delete_shared_data FROM accounts a JOIN account_deletion_requests d USING(account_id) WHERE d.deletion_timestamp<=$1 ORDER BY d.deletion_timestamp FOR UPDATE OF a,d SKIP LOCKED LIMIT 1`, e.Now()).Scan(&account, &shared)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	body, _ := json.Marshal(struct {
		UserID           string `json:"userId"`
		DeleteSharedData bool   `json:"deleteSharedData"`
	}{account.String(), shared})
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox(message_id,exchange,type,body) VALUES($1,'auth.profiles','profile.deleted',$2)`, uuid.New(), body)
	if err != nil {
		return false, err
	}
	if err = e.notifyAccount(ctx, tx, account, mailRequest{Template: "account_deleted"}); err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM accounts WHERE account_id=$1`, account)
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func normalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func validUsername(s string) bool {
	if len(s) < 5 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '_' || strings.Contains(s, "__") {
		return false
	}
	letters := ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
		if r >= 'a' && r <= 'z' {
			letters += string(r)
		} else if r == '1' {
			letters += "i"
		}
	}
	for _, word := range strings.Fields(assets.ForbiddenUsernames) {
		if strings.Contains(letters, word) {
			return false
		}
	}
	return true
}
