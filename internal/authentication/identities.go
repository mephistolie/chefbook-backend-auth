package authentication

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"strconv"
	"time"
)

type Identity struct{ Provider, Subject string }
type PreparedOAuth struct {
	URL                 string
	ExpirationTimestamp time.Time
}

func (e *Engine) GetIdentities(ctx context.Context, who Principal) ([]Identity, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT provider,subject FROM identities WHERE account_id=$1 ORDER BY provider`, who.AccountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Identity{}
	for rows.Next() {
		var i Identity
		if err = rows.Scan(&i.Provider, &i.Subject); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
func (e *Engine) PrepareIdentityOAuth(ctx context.Context, who Principal, provider, redirect string) (PreparedOAuth, error) {
	adapter := e.Providers[provider]
	if adapter == nil {
		return PreparedOAuth{}, ErrUnavailable
	}
	if !contains(e.OAuthRedirects, redirect) {
		return PreparedOAuth{}, ErrInvalid
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return PreparedOAuth{}, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return PreparedOAuth{}, err
	}
	state, err := randomToken()
	if err != nil {
		return PreparedOAuth{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return PreparedOAuth{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return PreparedOAuth{}, err
	}
	encrypted, err := e.Secrets.Encrypt([]byte(verifier), "oauth:"+state)
	if err != nil {
		return PreparedOAuth{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	link, err := adapter.Authorize(state, nonce, base64.RawURLEncoding.EncodeToString(sum[:]), redirect, false)
	if err != nil {
		return PreparedOAuth{}, err
	}
	expiry := e.Now().Add(5 * time.Minute)
	_, err = tx.ExecContext(ctx, `INSERT INTO oauth_requests(state_hash,provider,session_id,client_binding_hash,redirect_uri,nonce_hash,encrypted_code_verifier,expiration_timestamp) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, e.Secrets.Hash("state", "", state), provider, who.SessionID, e.Secrets.Hash("binding", "", strconv.FormatInt(who.SessionID, 10)), redirect, e.Secrets.Hash("nonce", "", nonce), encrypted, expiry)
	if err != nil {
		return PreparedOAuth{}, err
	}
	if err = tx.Commit(); err != nil {
		return PreparedOAuth{}, err
	}
	return PreparedOAuth{link, expiry}, nil
}
func (e *Engine) LinkIdentity(ctx context.Context, who Principal, grant, provider, code, state string) (bool, error) {
	adapter := e.Providers[provider]
	if adapter == nil {
		return false, ErrUnavailable
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return false, err
	}
	var redirect string
	var nonce, encrypted []byte
	err = tx.QueryRowContext(ctx, `DELETE FROM oauth_requests WHERE state_hash=$1 AND provider=$2 AND session_id=$3 AND client_binding_hash=$4 AND expiration_timestamp>$5 RETURNING redirect_uri,nonce_hash,encrypted_code_verifier`, e.Secrets.Hash("state", "", state), provider, who.SessionID, e.Secrets.Hash("binding", "", strconv.FormatInt(who.SessionID, 10)), e.Now()).Scan(&redirect, &nonce, &encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrCredentials
	}
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	verifier, err := e.Secrets.Decrypt(encrypted, "oauth:"+state)
	if err != nil {
		return false, err
	}
	identity, err := adapter.Exchange(ctx, code, redirect, string(verifier))
	if err != nil {
		return false, err
	}
	if identity.Subject == "" || provider == "google" && (identity.Nonce == "" || subtle.ConstantTimeCompare(nonce, e.Secrets.Hash("nonce", "", identity.Nonce)) != 1) {
		return false, ErrCredentials
	}
	tx, err = e.begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "identityLink", who); err != nil {
		return false, err
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT subject FROM identities WHERE account_id=$1 AND provider=$2`, who.AccountID, provider).Scan(&existing)
	if err == nil {
		if existing != identity.Subject {
			return false, ErrConflict
		}
		return false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identities(account_id,provider,subject) VALUES($1,$2,$3)`, who.AccountID, provider, identity.Subject)
	if err != nil {
		return false, conflict(err)
	}
	if err = e.invalidate(ctx, tx, who.AccountID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
func (e *Engine) UnlinkIdentity(ctx context.Context, who Principal, grant, provider string) error {
	if provider != "google" && provider != "vk" {
		return ErrInvalid
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "identityUnlink", who); err != nil {
		return err
	}
	var count int
	err = tx.QueryRowContext(ctx, `SELECT (CASE WHEN password_hash IS NULL THEN 0 ELSE 1 END)+(SELECT count(*) FROM identities WHERE account_id=$1 AND provider<>$2)+(SELECT count(*) FROM passkeys WHERE account_id=$1) FROM accounts WHERE account_id=$1`, who.AccountID, provider).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM identities WHERE account_id=$1 AND provider=$2`, who.AccountID, provider)
	if err != nil {
		return err
	}
	if err = e.invalidate(ctx, tx, who.AccountID); err != nil {
		return err
	}
	return tx.Commit()
}
