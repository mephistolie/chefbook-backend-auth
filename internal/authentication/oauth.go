package authentication

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
)

type ProviderIdentity struct {
	Subject, Email, Nonce string
	AuthenticatedAt       time.Time
}
type Provider interface {
	Authorize(state, nonce, challenge, redirect string, reauth bool) (string, error)
	Exchange(context.Context, string, string, string) (ProviderIdentity, error)
	Native(context.Context, string) (ProviderIdentity, error)
}
type OAuthOptions struct{ CredentialType, RedirectURI string }

func (e *Engine) providerMethods() []string {
	out := []string{}
	for _, name := range []string{"google", "vk"} {
		if e.Providers[name] != nil {
			out = append(out, name)
		}
	}
	return out
}
func (e *Engine) createOAuthChallenge(ctx context.Context, tx *sql.Tx, p Process, c *Challenge, flow string, o OAuthOptions) error {
	if o.CredentialType != "" && o.CredentialType != "idToken" && o.CredentialType != "authorizationCode" {
		return ErrInvalid
	}
	provider := e.Providers[c.Method]
	if provider == nil {
		return ErrUnavailable
	}
	nonce, err := randomToken()
	if err != nil {
		return err
	}
	if o.CredentialType == "idToken" {
		if c.Method != "google" || o.RedirectURI != "" {
			return ErrInvalid
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO google_authentication_steps(step_id,nonce_hash) VALUES($1,$2)`, c.ID, e.Secrets.Hash("nonce", "", nonce))
		c.Nonce = nonce
		return err
	}
	if !contains(e.OAuthRedirects, o.RedirectURI) {
		return ErrInvalid
	}
	state, err := randomToken()
	if err != nil {
		return err
	}
	verifier, err := randomToken()
	if err != nil {
		return err
	}
	encrypted, err := e.Secrets.Encrypt([]byte(verifier), "oauth:"+state)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(verifier))
	c.URL, err = provider.Authorize(state, nonce, base64.RawURLEncoding.EncodeToString(sum[:]), o.RedirectURI, sensitive(p.Purpose.Type))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO oauth_requests(state_hash,provider,step_id,client_binding_hash,redirect_uri,nonce_hash,encrypted_code_verifier,expiration_timestamp) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, e.Secrets.Hash("state", "", state), c.Method, c.ID, e.Secrets.Hash("binding", "", flow), o.RedirectURI, e.Secrets.Hash("nonce", "", nonce), encrypted, c.ExpirationTimestamp)
	return err
}

// Provider network calls happen after one-time OAuth state is committed consumed,
// outside our transition lock. The actual account/challenge is rechecked afterward.
func (e *Engine) attemptProvider(ctx context.Context, id, cid uuid.UUID, flow string, who Principal, proof Proof) (Attempt, error) {
	provider := e.Providers[proof.Method]
	if provider == nil {
		return Attempt{}, ErrUnavailable
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback()
	p, err := e.load(ctx, tx, id, flow, who)
	if err != nil {
		return Attempt{}, err
	}
	c, err := loadChallenge(ctx, tx, cid, id)
	if err != nil {
		return Attempt{}, err
	}
	if p.Status != "pending" || c.Status != "pending" || c.Method != proof.Method || !c.ExpirationTimestamp.After(e.Now()) {
		return Attempt{}, ErrConflict
	}
	next, err := e.next(ctx, tx, p)
	if err != nil {
		return Attempt{}, err
	}
	if !contains(next.Methods, c.Method) {
		return Attempt{}, ErrForbidden
	}
	var nonceHash []byte
	var redirect string
	var encrypted []byte
	if proof.IDToken != "" {
		if proof.Method != "google" || proof.Code != "" || proof.State != "" {
			return Attempt{}, ErrInvalid
		}
		err = tx.QueryRowContext(ctx, `SELECT nonce_hash FROM google_authentication_steps WHERE step_id=$1`, cid).Scan(&nonceHash)
	} else {
		err = tx.QueryRowContext(ctx, `DELETE FROM oauth_requests WHERE state_hash=$1 AND provider=$2 AND step_id=$3 AND client_binding_hash=$4 AND expiration_timestamp>$5 RETURNING redirect_uri,nonce_hash,encrypted_code_verifier`, e.Secrets.Hash("state", "", proof.State), proof.Method, cid, e.Secrets.Hash("binding", "", flow), e.Now()).Scan(&redirect, &nonceHash, &encrypted)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, ErrCredentials
	}
	if err != nil {
		return Attempt{}, err
	}
	if err = tx.Commit(); err != nil {
		return Attempt{}, err
	}
	var identity ProviderIdentity
	if proof.IDToken != "" {
		identity, err = provider.Native(ctx, proof.IDToken)
	} else {
		var verifier []byte
		verifier, err = e.Secrets.Decrypt(encrypted, "oauth:"+proof.State)
		if err == nil {
			identity, err = provider.Exchange(ctx, proof.Code, redirect, string(verifier))
		}
	}
	if err != nil {
		return Attempt{}, err
	}
	if identity.Subject == "" || proof.Method == "google" && (identity.Nonce == "" || subtle.ConstantTimeCompare(nonceHash, e.Secrets.Hash("nonce", "", identity.Nonce)) != 1) {
		return Attempt{}, ErrCredentials
	}
	if sensitive(p.Purpose.Type) && (identity.AuthenticatedAt.IsZero() || identity.AuthenticatedAt.Before(e.Now().Add(-e.ReuseTTL)) || identity.AuthenticatedAt.After(e.Now().Add(time.Minute))) {
		return Attempt{}, ErrForbidden
	}
	tx, err = e.begin(ctx)
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback()
	p, err = e.load(ctx, tx, id, flow, who)
	if err != nil {
		return Attempt{}, err
	}
	c, err = loadChallenge(ctx, tx, cid, id)
	if err != nil {
		return Attempt{}, err
	}
	if p.Status != "pending" || c.Status != "pending" || !c.ExpirationTimestamp.After(e.Now()) {
		return Attempt{}, ErrConflict
	}
	next, err = e.next(ctx, tx, p)
	if err != nil {
		return Attempt{}, err
	}
	if !contains(next.Methods, c.Method) {
		return Attempt{}, ErrForbidden
	}
	var account uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT i.account_id FROM identities i JOIN accounts a USING(account_id) WHERE i.provider=$1 AND i.subject=$2 AND a.blocking_timestamp IS NULL`, proof.Method, identity.Subject).Scan(&account)
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, ErrCredentials
	}
	if err != nil {
		return Attempt{}, err
	}
	if sensitive(p.Purpose.Type) && p.accountID.UUID != account {
		return Attempt{}, ErrCredentials
	}
	p.accountID = uuid.NullUUID{UUID: account, Valid: true}
	_, err = tx.ExecContext(ctx, `UPDATE authentications SET account_id=$2 WHERE authentication_id=$1`, id, account)
	if err != nil {
		return Attempt{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE authentication_steps SET status='completed',completion_timestamp=$2 WHERE step_id=$1`, cid, e.Now())
	if err != nil {
		return Attempt{}, err
	}
	c.Status = "completed"
	if err = e.cancelAlternatives(ctx, tx, p.ID, c.ID); err != nil {
		return Attempt{}, err
	}
	p.Next, err = e.next(ctx, tx, p)
	if err != nil {
		return Attempt{}, err
	}
	if len(p.Next.Methods) == 0 {
		if err = e.complete(ctx, tx, &p); err != nil {
			return Attempt{}, err
		}
	}
	p.Steps, err = e.steps(ctx, tx, p)
	if err != nil {
		return Attempt{}, err
	}
	if err = tx.Commit(); err != nil {
		return Attempt{}, err
	}
	return Attempt{c, p}, nil
}
func validateRedirect(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme != "" && u.Fragment == ""
}

func (e *Engine) AttemptProvider(ctx context.Context, id, cid uuid.UUID, flow string, who Principal, proof Proof) (Attempt, error) {
	result, err := e.attemptProvider(ctx, id, cid, flow, who, proof)
	if !errors.Is(err, ErrCredentials) {
		return result, err
	}
	tx, txErr := e.begin(ctx)
	if txErr != nil {
		return Attempt{}, txErr
	}
	defer tx.Rollback()
	p, txErr := e.load(ctx, tx, id, flow, who)
	if txErr != nil {
		return Attempt{}, txErr
	}
	c, txErr := loadChallenge(ctx, tx, cid, id)
	if txErr != nil {
		return Attempt{}, txErr
	}
	if p.Status != "pending" || c.Status != "pending" {
		return Attempt{}, ErrConflict
	}
	if _, txErr = tx.ExecContext(ctx, `UPDATE authentications SET failed_attempts=failed_attempts+1,status=CASE WHEN failed_attempts+1 >= $2 THEN 'failed' ELSE status END WHERE authentication_id=$1`, id, e.MaxAttempts); txErr != nil {
		return Attempt{}, txErr
	}
	if _, txErr = tx.ExecContext(ctx, `UPDATE authentication_steps SET failed_attempts=failed_attempts+1,status=CASE WHEN failed_attempts+1 >= $2 THEN 'failed' ELSE status END WHERE step_id=$1`, cid, e.MaxAttempts); txErr != nil {
		return Attempt{}, txErr
	}
	if txErr = tx.Commit(); txErr != nil {
		return Attempt{}, txErr
	}
	if p.failures+1 >= e.MaxAttempts {
		return Attempt{}, ErrAttempts
	}
	return result, err
}
