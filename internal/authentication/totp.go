package authentication

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"net/url"
	"time"
)

type TotpState struct {
	Enabled             bool
	ActivationTimestamp *time.Time
}
type TotpActivation struct {
	Secret, OtpauthURI  string
	ExpirationTimestamp time.Time
}
type BackupCodes struct {
	Codes               []string
	GenerationTimestamp time.Time
}
type BackupState struct {
	RemainingCount      int
	GenerationTimestamp *time.Time
}

func (e *Engine) GetTotp(ctx context.Context, who Principal) (TotpState, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return TotpState{}, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return TotpState{}, err
	}
	var at time.Time
	err = tx.QueryRowContext(ctx, `SELECT activation_timestamp FROM totp WHERE account_id=$1`, who.AccountID).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return TotpState{}, nil
	}
	if err != nil {
		return TotpState{}, err
	}
	return TotpState{true, &at}, nil
}
func (e *Engine) StartTotp(ctx context.Context, who Principal, grant string) (TotpActivation, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return TotpActivation{}, err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "totpEnrollment", who); err != nil {
		return TotpActivation{}, err
	}
	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM totp WHERE account_id=$1)`, who.AccountID).Scan(&exists)
	if err != nil {
		return TotpActivation{}, err
	}
	if exists {
		return TotpActivation{}, ErrConflict
	}
	secret := make([]byte, 20)
	if _, err = rand.Read(secret); err != nil {
		return TotpActivation{}, err
	}
	encrypted, err := e.Secrets.Encrypt(secret, who.AccountID.String())
	if err != nil {
		return TotpActivation{}, err
	}
	expiry := e.Now().Add(5 * time.Minute)
	_, err = tx.ExecContext(ctx, `INSERT INTO totp_activation_requests(account_id,session_id,encrypted_secret,expiration_timestamp) VALUES($1,$2,$3,$4) ON CONFLICT(account_id) DO UPDATE SET session_id=EXCLUDED.session_id,encrypted_secret=EXCLUDED.encrypted_secret,expiration_timestamp=EXCLUDED.expiration_timestamp`, who.AccountID, who.SessionID, encrypted, expiry)
	if err != nil {
		return TotpActivation{}, err
	}
	var email string
	if err = tx.QueryRowContext(ctx, `SELECT email FROM accounts WHERE account_id=$1`, who.AccountID).Scan(&email); err != nil {
		return TotpActivation{}, err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	uri := url.URL{Scheme: "otpauth", Host: "totp", Path: "/ChefBook:" + email}
	q := uri.Query()
	q.Set("secret", encoded)
	q.Set("issuer", "ChefBook")
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	uri.RawQuery = q.Encode()
	if err = tx.Commit(); err != nil {
		return TotpActivation{}, err
	}
	return TotpActivation{encoded, uri.String(), expiry}, nil
}
func (e *Engine) ConfirmTotp(ctx context.Context, who Principal, code string) (BackupCodes, error) {
	if !e.activationAttempts.allow(who.AccountID, e.Now()) {
		return BackupCodes{}, ErrAttempts
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return BackupCodes{}, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return BackupCodes{}, err
	}
	var encrypted []byte
	err = tx.QueryRowContext(ctx, `SELECT encrypted_secret FROM totp_activation_requests WHERE account_id=$1 AND session_id=$2 AND expiration_timestamp>$3 FOR UPDATE`, who.AccountID, who.SessionID, e.Now()).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupCodes{}, ErrInvalid
	}
	if err != nil {
		return BackupCodes{}, err
	}
	secret, err := e.Secrets.Decrypt(encrypted, who.AccountID.String())
	if err != nil {
		return BackupCodes{}, err
	}
	step, ok := totpStep(secret, code, e.Now(), -1)
	if !ok {
		return BackupCodes{}, ErrCredentials
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO totp(account_id,encrypted_secret,last_used_step,activation_timestamp) VALUES($1,$2,$3,$4)`, who.AccountID, encrypted, step, e.Now())
	if err != nil {
		return BackupCodes{}, conflict(err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM totp_activation_requests WHERE account_id=$1`, who.AccountID); err != nil {
		return BackupCodes{}, err
	}
	if err = e.invalidate(ctx, tx, who.AccountID); err != nil {
		return BackupCodes{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE account_id=$1 AND session_id<>$2`, who.AccountID, who.SessionID); err != nil {
		return BackupCodes{}, err
	}
	result, err := e.replaceBackupCodes(ctx, tx, who)
	if err != nil {
		return BackupCodes{}, err
	}
	if err = tx.Commit(); err != nil {
		return BackupCodes{}, err
	}
	return result, nil
}
func (e *Engine) DeleteTotp(ctx context.Context, who Principal, grant string) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "totpRemoval", who); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM totp WHERE account_id=$1`, who.AccountID); err != nil {
		return err
	}
	if err = e.invalidate(ctx, tx, who.AccountID); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) replaceBackupCodes(ctx context.Context, tx *sql.Tx, who Principal) (BackupCodes, error) {
	out := BackupCodes{Codes: make([]string, 10), GenerationTimestamp: e.Now()}
	if _, err := tx.ExecContext(ctx, `DELETE FROM backup_codes WHERE account_id=$1`, who.AccountID); err != nil {
		return out, err
	}
	for i := range out.Codes {
		token, err := randomToken()
		if err != nil {
			return out, err
		}
		out.Codes[i] = token
		_, err = tx.ExecContext(ctx, `INSERT INTO backup_codes(account_id,code_hash,generation_timestamp) VALUES($1,$2,$3)`, who.AccountID, e.Secrets.Hash("backup", who.AccountID.String(), token), out.GenerationTimestamp)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
func (e *Engine) RotateBackupCodes(ctx context.Context, who Principal, grant string) (BackupCodes, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return BackupCodes{}, err
	}
	defer tx.Rollback()
	if _, err = e.ConsumeGrant(ctx, tx, grant, "backupCodesRotation", who); err != nil {
		return BackupCodes{}, err
	}
	result, err := e.replaceBackupCodes(ctx, tx, who)
	if err != nil {
		return BackupCodes{}, err
	}
	if err = e.invalidate(ctx, tx, who.AccountID); err != nil {
		return BackupCodes{}, err
	}
	if err = tx.Commit(); err != nil {
		return BackupCodes{}, err
	}
	return result, nil
}
func (e *Engine) GetBackupCodes(ctx context.Context, who Principal) (BackupState, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return BackupState{}, err
	}
	defer tx.Rollback()
	if err = e.checkPrincipal(ctx, tx, who); err != nil {
		return BackupState{}, err
	}
	var out BackupState
	var at sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT count(*),max(generation_timestamp) FROM backup_codes WHERE account_id=$1`, who.AccountID).Scan(&out.RemainingCount, &at)
	if at.Valid {
		out.GenerationTimestamp = &at.Time
	}
	return out, err
}
