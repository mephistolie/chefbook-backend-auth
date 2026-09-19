package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/google/uuid"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/flow"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func opaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
func (r *Repository) CreateOAuthState(ctx context.Context, provider, redirect, binding string) (string, error) {
	if binding == "" || redirect == "" {
		return "", fail.GrpcInvalidBody
	}
	token, err := opaqueToken()
	if err != nil {
		return "", fail.GrpcUnknown
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO oauth_states(token_hash,provider,redirect_uri,binding_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, tokenHash(token), provider, redirect, tokenHash(binding), time.Now().Add(flow.TTL))
	if err != nil {
		return "", fail.GrpcUnknown
	}
	return token, nil
}
func (r *Repository) ConsumeOAuthState(ctx context.Context, provider, token, redirect, binding string) error {
	if token == "" || binding == "" {
		return authFail.GrpcInvalidCode
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE token_hash=$1 AND provider=$2 AND redirect_uri=$3 AND binding_hash=$4 AND expires_at>NOW()`, tokenHash(token), provider, redirect, tokenHash(binding))
	if err != nil {
		return fail.GrpcUnknown
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fail.GrpcUnknown
	}
	if n != 1 {
		return authFail.GrpcInvalidCode
	}
	return nil
}

func (r *Repository) ConsumeReauthentication(ctx context.Context, id uuid.UUID, token string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO reauthentication_proofs(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+interval '1 hour')`, tokenHash(token), id)
	if isUniqueViolationError(err) {
		return authFail.GrpcReauthentication
	}
	if err != nil {
		return fail.GrpcUnknown
	}
	return nil
}
func (r *Repository) CleanupAuthWorkflows(ctx context.Context) error {
	for _, table := range []string{"oauth_states", "email_deliveries", "email_bindings", "reauthentication_proofs"} {
		if _, err := r.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires_at<=NOW()`); err != nil {
			return fail.GrpcUnknown
		}
	}
	return nil
}
