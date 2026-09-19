package authentication

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (e *Engine) CreateChallenge(ctx context.Context, id uuid.UUID, flow, method string, who Principal, options ...OAuthOptions) (Challenge, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Challenge{}, err
	}
	defer tx.Rollback()
	p, err := e.load(ctx, tx, id, flow, who)
	if err != nil {
		return Challenge{}, err
	}
	if p.Status != "pending" {
		return Challenge{}, ErrConflict
	}
	next, err := e.next(ctx, tx, p)
	if err != nil {
		return Challenge{}, err
	}
	if !contains(next.Methods, method) {
		return Challenge{}, ErrForbidden
	}
	c := Challenge{ID: uuid.New(), Method: method, Status: "pending", ExpirationTimestamp: e.Now().Add(e.ChallengeTTL)}
	if c.ExpirationTimestamp.After(p.ExpirationTimestamp) {
		c.ExpirationTimestamp = p.ExpirationTimestamp
	}
	_, err = tx.ExecContext(ctx, `UPDATE authentication_steps SET status='cancelled' WHERE authentication_id=$1 AND type=$2 AND status='pending'`, id, StepType(method))
	if err != nil {
		return Challenge{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO authentication_steps(step_id,authentication_id,type,expiration_timestamp) VALUES($1,$2,$3,$4)`, c.ID, id, StepType(method), c.ExpirationTimestamp)
	if err != nil {
		return Challenge{}, err
	}
	if method == "google" || method == "vk" {
		var o OAuthOptions
		if len(options) > 0 {
			o = options[0]
		}
		if err = e.createOAuthChallenge(ctx, tx, p, &c, flow, o); err != nil {
			return Challenge{}, err
		}
	}
	if method == "passkey" {
		if e.Passkeys == nil {
			return Challenge{}, ErrUnavailable
		}
		ceremony, err := e.Passkeys.BeginAuthentication(c.ExpirationTimestamp)
		if err != nil {
			return Challenge{}, ErrUnavailable
		}
		c.PublicKey = ceremony.Options
		if _, err = tx.ExecContext(ctx, `INSERT INTO passkey_authentication_steps(step_id,challenge) VALUES($1,$2)`, c.ID, ceremony.Challenge); err != nil {
			return Challenge{}, err
		}
	}
	if method == "email" {
		if e.Mail == nil {
			return Challenge{}, ErrUnavailable
		}
		var email string
		err = tx.QueryRowContext(ctx, `SELECT email FROM registrations WHERE authentication_id=$1`, id).Scan(&email)
		if err != nil {
			return Challenge{}, err
		}
		code, err := randomCode()
		if err != nil {
			return Challenge{}, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO email_authentication_steps(step_id,email,code_hash) VALUES($1,$2,$3)`, c.ID, email, e.Secrets.Hash("email", c.ID.String(), code))
		if err != nil {
			return Challenge{}, err
		}
		if err = e.Mail.QueueCode(ctx, tx, email, code, c.ExpirationTimestamp); err != nil {
			return Challenge{}, err
		}
	}
	if err = e.hydrateStep(ctx, tx, p, &c); err != nil {
		return Challenge{}, err
	}
	if err = tx.Commit(); err != nil {
		return Challenge{}, err
	}
	return c, nil
}
func loadChallenge(ctx context.Context, tx *sql.Tx, id, process uuid.UUID) (Challenge, error) {
	var c Challenge
	err := tx.QueryRowContext(ctx, `SELECT step_id,type,status,expiration_timestamp FROM authentication_steps WHERE step_id=$1 AND authentication_id=$2 FOR UPDATE`, id, process).Scan(&c.ID, &c.Method, &c.Status, &c.ExpirationTimestamp)
	c.Method = StepMethod(c.Method)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrUnauthorized
	}
	return c, err
}
func (e *Engine) GetChallenge(ctx context.Context, id, challenge uuid.UUID, flow string, who Principal) (Challenge, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Challenge{}, err
	}
	defer tx.Rollback()
	p, err := e.load(ctx, tx, id, flow, who)
	if err != nil {
		return Challenge{}, err
	}
	c, err := loadChallenge(ctx, tx, challenge, id)
	if err == nil {
		err = e.hydrateStep(ctx, tx, p, &c)
	}
	return c, err
}
func (e *Engine) Attempt(ctx context.Context, id, challenge uuid.UUID, flow string, who Principal, proof Proof) (Attempt, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback()
	p, err := e.load(ctx, tx, id, flow, who)
	if err != nil {
		return Attempt{}, err
	}
	if p.Status != "pending" {
		return Attempt{}, ErrConflict
	}
	c, err := loadChallenge(ctx, tx, challenge, id)
	if err != nil {
		return Attempt{}, err
	}
	if c.Status != "pending" || !c.ExpirationTimestamp.After(e.Now()) {
		return Attempt{}, ErrConflict
	}
	if c.Method != proof.Method {
		return Attempt{}, ErrInvalid
	}
	next, err := e.next(ctx, tx, p)
	if err != nil {
		return Attempt{}, err
	}
	if !contains(next.Methods, c.Method) {
		return Attempt{}, ErrForbidden
	}
	err = e.verify(ctx, tx, &p, c, proof)
	if errors.Is(err, ErrCredentials) {
		_, updateErr := tx.ExecContext(ctx, `UPDATE authentications SET failed_attempts=failed_attempts+1,status=CASE WHEN failed_attempts+1 >= $2 THEN 'failed' ELSE status END WHERE authentication_id=$1`, id, e.MaxAttempts)
		if updateErr != nil {
			return Attempt{}, updateErr
		}
		_, updateErr = tx.ExecContext(ctx, `UPDATE authentication_steps SET failed_attempts=failed_attempts+1,status=CASE WHEN failed_attempts+1 >= $2 THEN 'failed' ELSE status END WHERE step_id=$1`, challenge, e.MaxAttempts)
		if updateErr != nil {
			return Attempt{}, updateErr
		}
		if updateErr = tx.Commit(); updateErr != nil {
			return Attempt{}, updateErr
		}
		if p.failures+1 >= e.MaxAttempts {
			return Attempt{}, ErrAttempts
		}
		return Attempt{}, ErrCredentials
	}
	if err != nil {
		return Attempt{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE authentication_steps SET status='completed',completion_timestamp=$2 WHERE step_id=$1`, challenge, e.Now())
	if err != nil {
		return Attempt{}, err
	}
	c.Status = "completed"
	if err = e.cancelAlternatives(ctx, tx, p.ID, c.ID); err != nil {
		return Attempt{}, err
	}
	if p.Purpose.Type == "signUp" {
		if c.Method == "email" {
			if err = e.registrationAvailable(ctx, tx, p.ID); errors.Is(err, ErrAccountExists) {
				return Attempt{}, e.failRegistration(ctx, tx, p.ID, err)
			} else if err != nil {
				return Attempt{}, err
			}
		}
		p.Next, err = e.next(ctx, tx, p)
		if err != nil {
			return Attempt{}, err
		}
		if len(p.Next.Methods) > 0 {
			p.Steps, err = e.steps(ctx, tx, p)
			if err != nil {
				return Attempt{}, err
			}
			if err = tx.Commit(); err != nil {
				return Attempt{}, err
			}
			return Attempt{c, p}, nil
		}
		if err = e.register(ctx, tx, &p); err != nil {
			if errors.Is(err, ErrAccountExists) {
				return Attempt{}, e.failRegistration(ctx, tx, p.ID, err)
			}
			return Attempt{}, err
		}
		err = e.complete(ctx, tx, &p)
	} else {
		p.Next, err = e.next(ctx, tx, p)
		if err == nil && len(p.Next.Methods) == 0 {
			err = e.complete(ctx, tx, &p)
		}
	}
	if err != nil {
		return Attempt{}, err
	}
	p.Steps, err = e.steps(ctx, tx, p)
	if err != nil {
		return Attempt{}, err
	}
	if err = e.hydrateStep(ctx, tx, p, &c); err != nil {
		return Attempt{}, err
	}
	if err = tx.Commit(); err != nil {
		return Attempt{}, err
	}
	return Attempt{Challenge: c, Authentication: p}, nil
}

// Use the configured work factor for both existing and nonexistent logins.
// Initialize on every branch before the lookup so the first call is not revealing.
func (e *Engine) dummyPassword() ([]byte, error) {
	e.dummyOnce.Do(func() {
		e.dummyPasswordHash, e.dummyPasswordError = bcrypt.GenerateFromPassword([]byte("not-an-account-password"), e.BcryptCost)
	})
	return e.dummyPasswordHash, e.dummyPasswordError
}

func (e *Engine) verify(ctx context.Context, tx *sql.Tx, p *Process, c Challenge, proof Proof) error {
	switch c.Method {
	case "registration":
		email := strings.ToLower(strings.TrimSpace(proof.Email))
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email {
			return ErrInvalid
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO registrations(authentication_id,email) VALUES($1,$2)`, p.ID, email)
		return err
	case "passwordSetup":
		if len(proof.Password) < 8 || len(proof.Password) > 72 {
			return ErrInvalid
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(proof.Password), e.BcryptCost)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE registrations SET password_hash=$2 WHERE authentication_id=$1`, p.ID, string(hash))
		return err
	case "passkey":
		return e.verifyPasskey(ctx, tx, p, c, proof)
	case "password":
		dummy, dummyErr := e.dummyPassword()
		if dummyErr != nil {
			return dummyErr
		}
		if (sensitive(p.Purpose.Type) && proof.Login != "") || (!sensitive(p.Purpose.Type) && proof.Login == "") {
			return ErrInvalid
		}
		var account uuid.UUID
		var hash sql.NullString
		var blocked sql.NullTime
		login := strings.ToLower(strings.TrimSpace(proof.Login))
		var err error
		if sensitive(p.Purpose.Type) {
			err = tx.QueryRowContext(ctx, `SELECT account_id,password_hash,blocking_timestamp FROM accounts WHERE account_id=$1 FOR UPDATE`, p.accountID.UUID).Scan(&account, &hash, &blocked)
		} else {
			err = tx.QueryRowContext(ctx, `SELECT account_id,password_hash,blocking_timestamp FROM accounts WHERE email=$1 OR username=$1 FOR UPDATE`, login).Scan(&account, &hash, &blocked)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		compareHash := string(dummy)
		if hash.Valid {
			compareHash = hash.String
		}
		valid := bcrypt.CompareHashAndPassword([]byte(compareHash), []byte(proof.Password)) == nil
		if err != nil || !valid || !hash.Valid || blocked.Valid {
			return ErrCredentials
		}
		p.accountID = uuid.NullUUID{UUID: account, Valid: true}
		_, err = tx.ExecContext(ctx, `UPDATE authentications SET account_id=$2 WHERE authentication_id=$1`, p.ID, account)
		return err
	case "email":
		var hash []byte
		err := tx.QueryRowContext(ctx, `SELECT code_hash FROM email_authentication_steps WHERE step_id=$1`, c.ID).Scan(&hash)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(hash, e.Secrets.Hash("email", c.ID.String(), proof.Code)) != 1 {
			return ErrCredentials
		}
		return nil
	case "totp":
		if !p.accountID.Valid {
			return ErrForbidden
		}
		var encrypted []byte
		var last int64
		err := tx.QueryRowContext(ctx, `SELECT encrypted_secret,last_used_step FROM totp WHERE account_id=$1 FOR UPDATE`, p.accountID.UUID).Scan(&encrypted, &last)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCredentials
		}
		if err != nil {
			return err
		}
		secret, err := e.Secrets.Decrypt(encrypted, p.accountID.UUID.String())
		if err != nil {
			return err
		}
		step, ok := totpStep(secret, proof.Code, e.Now(), last)
		if !ok {
			return ErrCredentials
		}
		_, err = tx.ExecContext(ctx, `UPDATE totp SET last_used_step=$2 WHERE account_id=$1`, p.accountID.UUID, step)
		return err
	case "backupCode":
		if !p.accountID.Valid {
			return ErrForbidden
		}
		var one int
		err := tx.QueryRowContext(ctx, `DELETE FROM backup_codes WHERE account_id=$1 AND code_hash=$2 RETURNING 1`, p.accountID.UUID, e.Secrets.Hash("backup", p.accountID.UUID.String(), proof.Code)).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCredentials
		}
		return err
	}
	return ErrUnavailable
}
func (e *Engine) register(ctx context.Context, tx *sql.Tx, p *Process) error {
	account := uuid.New()
	var email string
	var password sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT email,password_hash FROM registrations WHERE authentication_id=$1`, p.ID).Scan(&email, &password)
	if err != nil {
		return err
	}
	if !password.Valid {
		return ErrForbidden
	}
	// Existence is disclosed only AFTER the flow proves ownership of its email.
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE email=$1)`, email).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrAccountExists
	}
	// A unique-key conflict is visible only AFTER email ownership proof.
	var inserted uuid.UUID
	err = tx.QueryRowContext(ctx, `INSERT INTO accounts(account_id,email,email_verification_timestamp,password_hash,password_change_timestamp) VALUES($1,$2,$3::timestamptz,$4,CASE WHEN $4::text IS NULL THEN NULL ELSE $3::timestamptz END) ON CONFLICT(email) DO NOTHING RETURNING account_id`, account, email, e.Now(), password).Scan(&inserted)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccountExists
	}
	if err != nil {
		var sqlState interface{ SQLState() string }
		if errors.As(err, &sqlState) && sqlState.SQLState() == "23505" {
			return ErrConflict
		}
		return err
	}
	body, _ := json.Marshal(struct {
		UserID string `json:"userId"`
	}{account.String()})
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox(message_id,exchange,type,body) VALUES($1,'auth.profiles','profile.created',$2)`, uuid.New(), body)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM registrations WHERE authentication_id=$1`, p.ID)
	if err != nil {
		return err
	}
	p.accountID = uuid.NullUUID{UUID: account, Valid: true}
	return nil
}
