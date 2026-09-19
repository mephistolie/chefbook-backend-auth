package authentication

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	key "github.com/mephistolie/chefbook-backend-auth/pkg/passkey"
)

type Passkey struct {
	ID                          uuid.UUID
	Name                        string
	CreationTimestamp           time.Time
	LastUseTimestamp            *time.Time
	Transports                  []string
	BackupEligible, BackupState bool
}
type PasskeyRequest struct {
	ID                  uuid.UUID
	PublicKey           json.RawMessage
	ExpirationTimestamp time.Time
}

func (e *Engine) passkeyAccount(ctx context.Context, tx *sql.Tx, id uuid.UUID) (key.Account, error) {
	a := key.Account{ID: id}
	var blocked sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT email,blocking_timestamp FROM accounts WHERE account_id=$1`, id).Scan(&a.Name, &blocked)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrCredentials
	}
	if err != nil {
		return a, err
	}
	if blocked.Valid {
		return a, ErrForbidden
	}
	rows, err := tx.QueryContext(ctx, `SELECT credential_id,public_key,sign_count,backup_eligible,backup_state FROM passkeys WHERE account_id=$1`, id)
	if err != nil {
		return a, err
	}
	defer rows.Close()
	for rows.Next() {
		var c key.Credential
		if err = rows.Scan(&c.ID, &c.PublicKey, &c.SignCount, &c.BackupEligible, &c.BackupState); err != nil {
			return a, err
		}
		a.Credentials = append(a.Credentials, c)
	}
	return a, rows.Err()
}
func (e *Engine) GetPasskeys(ctx context.Context, who Principal) ([]Passkey, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT passkey_id,name,creation_timestamp,last_use_timestamp,backup_eligible,backup_state FROM passkeys WHERE account_id=$1 ORDER BY creation_timestamp`, who.AccountID)
	if err != nil {
		return nil, err
	}
	out := []Passkey{}
	for rows.Next() {
		var p Passkey
		var last sql.NullTime
		if err = rows.Scan(&p.ID, &p.Name, &p.CreationTimestamp, &last, &p.BackupEligible, &p.BackupState); err != nil {
			rows.Close()
			return nil, err
		}
		if last.Valid {
			p.LastUseTimestamp = &last.Time
		}
		p.Transports = []string{}
		out = append(out, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		rows, err = tx.QueryContext(ctx, `SELECT transport FROM passkey_transports WHERE passkey_id=$1 ORDER BY transport`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var transport string
			if err = rows.Scan(&transport); err != nil {
				rows.Close()
				return nil, err
			}
			out[i].Transports = append(out[i].Transports, transport)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (e *Engine) StartPasskey(ctx context.Context, who Principal, grant string) (PasskeyRequest, error) {
	if e.Passkeys == nil {
		return PasskeyRequest{}, ErrUnavailable
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return PasskeyRequest{}, err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "passkeyEnrollment", who); err != nil {
		return PasskeyRequest{}, err
	}
	a, err := e.passkeyAccount(ctx, tx, who.AccountID)
	if err != nil {
		return PasskeyRequest{}, err
	}
	expiry := e.Now().Add(5 * time.Minute)
	ceremony, err := e.Passkeys.BeginRegistration(a, expiry)
	if err != nil {
		return PasskeyRequest{}, ErrInvalid
	}
	id := uuid.New()
	_, err = tx.ExecContext(ctx, `INSERT INTO passkey_registration_requests(request_id,session_id,challenge,expiration_timestamp) VALUES($1,$2,$3,$4)`, id, who.SessionID, ceremony.Challenge, expiry)
	if err != nil {
		return PasskeyRequest{}, err
	}
	if err = tx.Commit(); err != nil {
		return PasskeyRequest{}, err
	}
	return PasskeyRequest{id, ceremony.Options, expiry}, nil
}
func (e *Engine) RegisterPasskey(ctx context.Context, who Principal, id uuid.UUID, name string, response []byte) (Passkey, error) {
	if e.Passkeys == nil {
		return Passkey{}, ErrUnavailable
	}
	if len(name) == 0 || len(name) > 128 {
		return Passkey{}, ErrInvalid
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return Passkey{}, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return Passkey{}, err
	}
	var challenge []byte
	var expiry time.Time
	err = tx.QueryRowContext(ctx, `SELECT challenge,expiration_timestamp FROM passkey_registration_requests WHERE request_id=$1 AND session_id=$2 AND expiration_timestamp>$3 FOR UPDATE`, id, who.SessionID, e.Now()).Scan(&challenge, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return Passkey{}, ErrInvalid
	}
	if err != nil {
		return Passkey{}, err
	}
	a, err := e.passkeyAccount(ctx, tx, who.AccountID)
	if err != nil {
		return Passkey{}, err
	}
	credential, err := e.Passkeys.VerifyRegistration(a, challenge, expiry, response)
	if err != nil {
		return Passkey{}, ErrCredentials
	}
	p := Passkey{ID: uuid.New(), Name: name, CreationTimestamp: e.Now(), Transports: credential.Transports, BackupEligible: credential.BackupEligible, BackupState: credential.BackupState}
	_, err = tx.ExecContext(ctx, `INSERT INTO passkeys(passkey_id,account_id,credential_id,public_key,name,sign_count,backup_eligible,backup_state,creation_timestamp) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, p.ID, who.AccountID, credential.ID, credential.PublicKey, name, credential.SignCount, credential.BackupEligible, credential.BackupState, p.CreationTimestamp)
	if err != nil {
		return Passkey{}, conflict(err)
	}
	for _, transport := range credential.Transports {
		if _, err = tx.ExecContext(ctx, `INSERT INTO passkey_transports(passkey_id,transport) VALUES($1,$2) ON CONFLICT DO NOTHING`, p.ID, transport); err != nil {
			return Passkey{}, err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM passkey_registration_requests WHERE request_id=$1`, id); err != nil {
		return Passkey{}, err
	}
	if err = e.invalidate(ctx, tx, who.AccountID); err != nil {
		return Passkey{}, err
	}
	if err = tx.Commit(); err != nil {
		return Passkey{}, err
	}
	return p, nil
}
func (e *Engine) RenamePasskey(ctx context.Context, who Principal, id uuid.UUID, name string) (Passkey, error) {
	if name == "" || len(name) > 128 {
		return Passkey{}, ErrInvalid
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return Passkey{}, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return Passkey{}, err
	}
	var p Passkey
	var last sql.NullTime
	err = tx.QueryRowContext(ctx, `UPDATE passkeys SET name=$3 WHERE passkey_id=$1 AND account_id=$2 RETURNING passkey_id,name,creation_timestamp,last_use_timestamp,backup_eligible,backup_state`, id, who.AccountID, name).Scan(&p.ID, &p.Name, &p.CreationTimestamp, &last, &p.BackupEligible, &p.BackupState)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	if last.Valid {
		p.LastUseTimestamp = &last.Time
	}
	rows, err := tx.QueryContext(ctx, `SELECT transport FROM passkey_transports WHERE passkey_id=$1`, id)
	if err != nil {
		return p, err
	}
	p.Transports = []string{}
	for rows.Next() {
		var t string
		if err = rows.Scan(&t); err != nil {
			rows.Close()
			return p, err
		}
		p.Transports = append(p.Transports, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	return p, tx.Commit()
}
func (e *Engine) DeletePasskey(ctx context.Context, who Principal, grant string, id uuid.UUID) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "passkeyRemoval", who); err != nil {
		return err
	}
	var count int
	err = tx.QueryRowContext(ctx, `SELECT (CASE WHEN password_hash IS NULL THEN 0 ELSE 1 END)+(SELECT count(*) FROM identities WHERE account_id=$1)+(SELECT count(*) FROM passkeys WHERE account_id=$1 AND passkey_id<>$2) FROM accounts WHERE account_id=$1`, who.AccountID, id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM passkeys WHERE account_id=$1 AND passkey_id=$2`, who.AccountID, id); err != nil {
		return err
	}
	if err = e.invalidate(ctx, tx, who.AccountID); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) verifyPasskey(ctx context.Context, tx *sql.Tx, p *Process, c Challenge, proof Proof) error {
	if e.Passkeys == nil {
		return ErrUnavailable
	}
	_, account, err := key.AssertionIdentity(proof.Credential)
	if err != nil {
		return ErrCredentials
	}
	if sensitive(p.Purpose.Type) && account != p.accountID.UUID {
		return ErrCredentials
	}
	a, err := e.passkeyAccount(ctx, tx, account)
	if err != nil {
		return err
	}
	var challenge []byte
	err = tx.QueryRowContext(ctx, `SELECT challenge FROM passkey_authentication_steps WHERE step_id=$1`, c.ID).Scan(&challenge)
	if err != nil {
		return err
	}
	cred, err := e.Passkeys.VerifyAuthentication(a, challenge, c.ExpirationTimestamp, proof.Credential)
	if err != nil {
		return ErrCredentials
	}
	if _, err = tx.ExecContext(ctx, `UPDATE passkeys SET sign_count=$2,backup_state=$3,last_use_timestamp=$4 WHERE credential_id=$1 AND account_id=$5`, cred.ID, cred.SignCount, cred.BackupState, e.Now(), account); err != nil {
		return err
	}
	p.accountID = uuid.NullUUID{UUID: account, Valid: true}
	_, err = tx.ExecContext(ctx, `UPDATE authentications SET account_id=$2 WHERE authentication_id=$1`, p.ID, account)
	return err
}
