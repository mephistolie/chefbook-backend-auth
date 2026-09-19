package authentication

import (
	"context"
	"strings"
)

// Cleanup only expires temporary state. Completed evidence lives at least through
// its reuse window; it never deletes accounts or pending outgoing events.
func (e *Engine) Cleanup(ctx context.Context) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM oauth_requests WHERE expiration_timestamp<$1`,
		`DELETE FROM email_change_requests WHERE expiration_timestamp<$1`,
		`DELETE FROM password_reset_requests WHERE expiration_timestamp<$1`,
		`DELETE FROM totp_activation_requests WHERE expiration_timestamp<$1`,
		`DELETE FROM passkey_registration_requests WHERE expiration_timestamp<$1`,
		`DELETE FROM authentications WHERE expiration_timestamp<$1 AND (completion_timestamp IS NULL OR completion_timestamp<$2) AND (confirmation_expiration_timestamp IS NULL OR confirmation_expiration_timestamp<$1)`,
		`DELETE FROM sessions WHERE expiration_timestamp<$1`,
	} {
		var args = []any{e.Now()}
		if strings.Contains(q, "$2") {
			args = append(args, e.Now().Add(-e.ReuseTTL))
		}
		if _, err = tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
