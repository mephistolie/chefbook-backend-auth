package authentication

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// StepType is the persisted/public discriminator. Provider adapters retain their
// provider identifier; it is not interchangeable with the kind of a workflow step.
func StepType(method string) string {
	switch method {
	case "password", "email", "totp", "backupCode", "google", "vk", "passkey":
		return method + "Verification"
	default:
		return method
	}
}
func StepMethod(kind string) string {
	switch kind {
	case "passwordVerification":
		return "password"
	case "emailVerification":
		return "email"
	case "totpVerification":
		return "totp"
	case "backupCodeVerification":
		return "backupCode"
	case "googleVerification":
		return "google"
	case "vkVerification":
		return "vk"
	case "passkeyVerification":
		return "passkey"
	default:
		return kind
	}
}

func (e *Engine) cancelAlternatives(ctx context.Context, tx *sql.Tx, process, accepted uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `UPDATE authentication_steps SET status='cancelled' WHERE authentication_id=$1 AND step_id<>$2 AND status='pending'`, process, accepted)
	return err
}

func (e *Engine) registrationAvailable(ctx context.Context, tx *sql.Tx, id uuid.UUID) error {
	var exists bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM registrations r JOIN accounts a ON a.email=r.email WHERE r.authentication_id=$1)`, id).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return ErrAccountExists
	}
	return nil
}

// A proved existing email terminates the sign-up, without granting access or
// changing that account. Commit the terminal result even though HTTP reports 409.
func (e *Engine) failRegistration(ctx context.Context, tx *sql.Tx, id uuid.UUID, reason error) error {
	if _, err := tx.ExecContext(ctx, `UPDATE authentications SET status='failed' WHERE authentication_id=$1`, id); err != nil {
		return err
	}
	if err := e.cancelAlternatives(ctx, tx, id, uuid.Nil); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registrations SET password_hash=NULL WHERE authentication_id=$1`, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return reason
}

func (e *Engine) steps(ctx context.Context, tx *sql.Tx, p Process) ([]Challenge, error) {
	rows, err := tx.QueryContext(ctx, `SELECT step_id,type,status,expiration_timestamp FROM authentication_steps WHERE authentication_id=$1 ORDER BY creation_timestamp,step_id`, p.ID)
	if err != nil {
		return nil, err
	}
	result := []Challenge{}
	for rows.Next() {
		var c Challenge
		if err = rows.Scan(&c.ID, &c.Method, &c.Status, &c.ExpirationTimestamp); err != nil {
			rows.Close()
			return nil, err
		}
		c.Method = StepMethod(c.Method)
		result = append(result, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range result {
		if err = e.hydrateStep(ctx, tx, p, &result[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// WebAuthn public options are reconstructible from typed storage. Only the
// stored challenge is exposed; a GET never creates a new ceremony or trust.
func (e *Engine) hydrateStep(ctx context.Context, tx *sql.Tx, p Process, c *Challenge) error {
	if c.Method != "passkey" {
		return nil
	}
	if e.Passkeys == nil {
		return ErrUnavailable
	}
	var challenge []byte
	err := tx.QueryRowContext(ctx, `SELECT challenge FROM passkey_authentication_steps WHERE step_id=$1`, c.ID).Scan(&challenge)
	if err == nil {
		c.PublicKey, err = e.Passkeys.AuthenticationOptions(challenge, c.ExpirationTimestamp, e.Now())
	}
	return err
}
