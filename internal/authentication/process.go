package authentication

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

func (e *Engine) Start(ctx context.Context, r StartRequest, who Principal) (Process, error) {
	var p Process
	if !validPurpose(r.Purpose.Type) {
		return p, ErrInvalid
	}
	if sensitive(r.Purpose.Type) && (who.AccountID == uuid.Nil || who.SessionID <= 0) {
		return p, ErrForbidden
	}
	flow, err := randomToken()
	if err != nil {
		return p, err
	}
	p = Process{ID: uuid.New(), Purpose: r.Purpose, Status: "pending", ExpirationTimestamp: e.Now().Add(e.FlowTTL), FlowToken: flow, Next: Next{Methods: []string{}}}
	tx, err := e.begin(ctx)
	if err != nil {
		return Process{}, err
	}
	defer tx.Rollback()
	var account, session any
	if sensitive(r.Purpose.Type) {
		if err = e.checkPurposePrincipal(ctx, tx, who, r.Purpose.Type); err != nil {
			return Process{}, err
		}
		account, session = who.AccountID, who.SessionID
		p.accountID = uuid.NullUUID{UUID: who.AccountID, Valid: true}
		p.sessionID = sql.NullInt64{Int64: who.SessionID, Valid: true}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO authentications(authentication_id,purpose,account_id,session_id,flow_token_hash,expiration_timestamp) VALUES($1,$2,$3,$4,$5,$6)`, p.ID, p.Purpose.Type, account, session, e.Secrets.Hash("flow", "", flow), p.ExpirationTimestamp)
	if err != nil {
		return Process{}, err
	}
	p.Next, err = e.next(ctx, tx, p)
	if err != nil {
		return Process{}, err
	}
	if sensitive(p.Purpose.Type) {
		reusable, err := e.reusable(ctx, tx, p)
		if err != nil {
			return Process{}, err
		}
		if reusable {
			if err = e.complete(ctx, tx, &p); err != nil {
				return Process{}, err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return Process{}, err
	}
	return p, nil
}

func (e *Engine) checkRecoveryPrincipal(ctx context.Context, tx *sql.Tx, p Principal) error {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions s JOIN accounts a USING(account_id) WHERE s.session_id=$1 AND s.account_id=$2 AND s.expiration_timestamp>$3 AND a.blocking_timestamp IS NULL)`, p.SessionID, p.AccountID, e.Now()).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func (e *Engine) load(ctx context.Context, tx *sql.Tx, id uuid.UUID, flow string, who Principal) (Process, error) {
	p := Process{Next: Next{Methods: []string{}}}
	var hash []byte
	var invalid sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT authentication_id,purpose,status,account_id,session_id,flow_token_hash,failed_attempts,expiration_timestamp,invalidation_timestamp FROM authentications WHERE authentication_id=$1 FOR UPDATE`, id).Scan(&p.ID, &p.Purpose.Type, &p.Status, &p.accountID, &p.sessionID, &hash, &p.failures, &p.ExpirationTimestamp, &invalid)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrUnauthorized
	}
	if err != nil {
		return p, err
	}
	if subtle.ConstantTimeCompare(hash, e.Secrets.Hash("flow", "", flow)) != 1 || invalid.Valid || !p.ExpirationTimestamp.After(e.Now()) {
		return p, ErrUnauthorized
	}
	if sensitive(p.Purpose.Type) {
		if !p.accountID.Valid || !p.sessionID.Valid || p.accountID.UUID != who.AccountID || p.sessionID.Int64 != who.SessionID {
			return p, ErrForbidden
		}
		if err = e.checkPurposePrincipal(ctx, tx, who, p.Purpose.Type); err != nil {
			return p, err
		}
	}
	return p, nil
}
func (e *Engine) Get(ctx context.Context, id uuid.UUID, flow string, who Principal) (Process, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Process{}, err
	}
	defer tx.Rollback()
	p, err := e.load(ctx, tx, id, flow, who)
	if err != nil {
		return Process{}, err
	}
	p.Next, err = e.next(ctx, tx, p)
	if err == nil {
		p.Steps, err = e.steps(ctx, tx, p)
	}
	return p, err
}
func (e *Engine) next(ctx context.Context, tx *sql.Tx, p Process) (Next, error) {
	n := Next{Methods: []string{}}
	if p.Status != "pending" {
		return n, nil
	}
	if p.Purpose.Type == "signUp" {
		var exists, verified, credential bool
		err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM registrations WHERE authentication_id=$1), EXISTS(SELECT 1 FROM authentication_steps WHERE authentication_id=$1 AND type='emailVerification' AND status='completed'), EXISTS(SELECT 1 FROM authentication_steps WHERE authentication_id=$1 AND type='passwordSetup' AND status='completed')`, p.ID).Scan(&exists, &verified, &credential)
		if err != nil {
			return n, err
		}
		if !exists {
			n.Methods = []string{"registration"}
			return n, nil
		}
		if !verified {
			n.Methods = []string{"email"}
			return n, nil
		}
		if credential {
			return n, nil
		}
		n.Methods = []string{"passwordSetup"}
		return n, nil
	}
	var first bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM authentication_steps WHERE authentication_id=$1 AND status='completed' AND type IN ('passwordVerification','googleVerification','vkVerification','passkeyVerification'))`, p.ID).Scan(&first)
	if err != nil {
		return n, err
	}
	if !first {
		n.Methods = append([]string{"password"}, e.providerMethods()...)
		if e.Passkeys != nil {
			n.Methods = append(n.Methods, "passkey")
		}
		return n, nil
	}
	if !p.accountID.Valid {
		return n, ErrForbidden
	}
	var totp bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM totp WHERE account_id=$1)`, p.accountID.UUID).Scan(&totp)
	if err != nil {
		return n, err
	}
	if totp {
		var second bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM authentication_steps WHERE authentication_id=$1 AND status='completed' AND type IN ('totpVerification','backupCodeVerification','passkeyVerification'))`, p.ID).Scan(&second)
		if err != nil {
			return n, err
		}
		if !second {
			n.Methods = []string{"totp", "backupCode"}
		}
	}
	return n, nil
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func (e *Engine) reusable(ctx context.Context, tx *sql.Tx, p Process) (bool, error) {
	var ok bool
	// Evidence is from one prior process; derived completions have no challenges.
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM authentications a WHERE a.account_id=$1 AND a.session_id=$2 AND a.status='completed' AND a.invalidation_timestamp IS NULL AND EXISTS(SELECT 1 FROM authentication_steps c WHERE c.authentication_id=a.authentication_id AND c.status='completed' AND c.type IN ('passwordVerification','googleVerification','vkVerification','passkeyVerification') AND c.completion_timestamp>$3) AND (NOT EXISTS(SELECT 1 FROM totp WHERE account_id=$1) OR EXISTS(SELECT 1 FROM authentication_steps c WHERE c.authentication_id=a.authentication_id AND c.status='completed' AND c.type IN ('totpVerification','backupCodeVerification','passkeyVerification') AND c.completion_timestamp>$3)))`, p.accountID.UUID, p.sessionID.Int64, e.Now().Add(-e.ReuseTTL)).Scan(&ok)
	return ok, err
}
func (e *Engine) complete(ctx context.Context, tx *sql.Tx, p *Process) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	expiry := e.Now().Add(e.GrantTTL)
	_, err = tx.ExecContext(ctx, `UPDATE authentications SET status='completed',account_id=$2,completion_timestamp=$3,confirmation_token_hash=$4,confirmation_expiration_timestamp=$5 WHERE authentication_id=$1`, p.ID, p.accountID.UUID, e.Now(), e.Secrets.Hash("grant", "", token), expiry)
	if err != nil {
		return err
	}
	p.Status = "completed"
	p.Next = Next{Methods: []string{}}
	p.ConfirmationToken = token
	p.ConfirmationExpirationTimestamp = &expiry
	return nil
}

// ConsumeGrant must run in the same transaction as the authorized action.
func (e *Engine) ConsumeGrant(ctx context.Context, tx *sql.Tx, token, purpose string, who Principal) (uuid.UUID, error) {
	var id uuid.UUID
	var account uuid.UUID
	var session sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT authentication_id,account_id,session_id FROM authentications WHERE confirmation_token_hash=$1 AND purpose=$2 AND status='completed' AND invalidation_timestamp IS NULL AND confirmation_expiration_timestamp>$3 FOR UPDATE`, e.Secrets.Hash("grant", "", token), purpose, e.Now()).Scan(&id, &account, &session)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrForbidden
	}
	if err != nil {
		return uuid.Nil, err
	}
	if sensitive(purpose) {
		if account != who.AccountID || !session.Valid || session.Int64 != who.SessionID {
			return uuid.Nil, ErrForbidden
		}
		if err = e.checkPurposePrincipal(ctx, tx, who, purpose); err != nil {
			return uuid.Nil, err
		}
	}
	var blocked sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT blocking_timestamp FROM accounts WHERE account_id=$1 FOR UPDATE`, account).Scan(&blocked)
	if err != nil {
		return uuid.Nil, err
	}
	if blocked.Valid {
		return uuid.Nil, ErrForbidden
	}
	_, err = tx.ExecContext(ctx, `UPDATE authentications SET confirmation_token_hash=NULL,confirmation_expiration_timestamp=NULL WHERE authentication_id=$1`, id)
	return account, err
}

func (e *Engine) checkPrincipal(ctx context.Context, tx *sql.Tx, p Principal) error {
	if err := e.checkRecoveryPrincipal(ctx, tx, p); err != nil {
		return err
	}
	var deleting bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account_deletion_requests WHERE account_id=$1)`, p.AccountID).Scan(&deleting)
	if err != nil {
		return err
	}
	if deleting {
		return ErrForbidden
	}
	return nil
}
func (e *Engine) checkPurposePrincipal(ctx context.Context, tx *sql.Tx, p Principal, purpose string) error {
	if purpose == "accountDeletion" {
		return e.checkRecoveryPrincipal(ctx, tx, p)
	}
	return e.checkPrincipal(ctx, tx, p)
}
