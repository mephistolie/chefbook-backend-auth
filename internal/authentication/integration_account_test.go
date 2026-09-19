package authentication

import (
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestIntegrationDeletionDeadlineAndRestrictions(t *testing.T) {
	e := integrationEngine(t)
	who, tokens, email := integrationSession(t, e)
	ctx := testContext(t)
	if _, err := e.PatchDeletion(ctx, who, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing deletion: %v", err)
	}
	proof := provePassword(t, e, "accountDeletion", who, email)
	deletion, err := e.RequestDeletion(ctx, who, proof.ConfirmationToken, false, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	patched, err := e.PatchDeletion(ctx, who, true)
	if err != nil || !patched.DeletionTimestamp.Equal(deletion.DeletionTimestamp) || !patched.DeleteSharedData {
		t.Fatal("deadline changed", err)
	}
	if err = e.SetUsername(ctx, who, "validusername"); !errors.Is(err, ErrForbidden) {
		t.Fatal("deleting account allowed username mutation", err)
	}
	now := deletion.DeletionTimestamp.Add(time.Second)
	e.Now = func() time.Time { return now }
	if err = e.CancelDeletion(ctx, who); !errors.Is(err, ErrConflict) {
		t.Fatal("expired deletion restored", err)
	}
	if _, err = e.PatchDeletion(ctx, who, false); !errors.Is(err, ErrConflict) {
		t.Fatal("expired deletion policy changed", err)
	}
	if _, err = e.Refresh(ctx, tokens.SessionID, tokens.RefreshToken, "127.0.0.1", "test", integrationIssuer{}, time.Minute, time.Hour); !errors.Is(err, ErrForbidden) {
		t.Fatal("expired deletion refreshed", err)
	}
	deleted, err := e.DeleteDueAccount(ctx)
	if err != nil || !deleted {
		t.Fatal("final deletion failed", err)
	}
	var count int
	if err = e.DB.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE account_id=$1`, who.AccountID).Scan(&count); err != nil || count != 0 {
		t.Fatal("account still exists", err)
	}
	if err = e.DB.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE type='profile.deleted' AND body->>'userId'=$1`, who.AccountID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatal("deletion event missing", err)
	}
}
func mailToken(t *testing.T, e *Engine, email, template string) string {
	t.Helper()
	var link string
	err := e.DB.QueryRowContext(testContext(t), `SELECT body->>'url' FROM outbox WHERE exchange='mail' AND body->>'to'=$1 AND body->>'template'=$2 ORDER BY creation_timestamp DESC LIMIT 1`, email, template).Scan(&link)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}
func TestIntegrationEmailChangeRequiresBothAddresses(t *testing.T) {
	e := integrationEngine(t)
	who, _, email := integrationSession(t, e)
	ctx := testContext(t)
	proof := provePassword(t, e, "emailChange", who, email)
	next := "changed-" + email
	base := "https://example.test/email"
	if err := e.ChangeEmail(ctx, who, proof.ConfirmationToken, next, base); err != nil {
		t.Fatal(err)
	}
	old := mailToken(t, e, email, "email_change_previous")
	result, err := e.ConfirmEmail(ctx, old, base)
	if err != nil || result != "pendingNewEmail" {
		t.Fatal(result, err)
	}
	var stored string
	if err = e.DB.QueryRowContext(ctx, `SELECT email FROM accounts WHERE account_id=$1`, who.AccountID).Scan(&stored); err != nil || stored != email {
		t.Fatal("changed before new proof", err)
	}
	if _, err = e.ConfirmEmail(ctx, old, base); !errors.Is(err, ErrInvalid) {
		t.Fatal("old token replay accepted", err)
	}
	fresh := mailToken(t, e, next, "email_change_new")
	result, err = e.ConfirmEmail(ctx, fresh, base)
	if err != nil || result != "changed" {
		t.Fatal(result, err)
	}
	if err = e.DB.QueryRowContext(ctx, `SELECT email FROM accounts WHERE account_id=$1`, who.AccountID).Scan(&stored); err != nil || stored != next {
		t.Fatal("new address not saved", err)
	}
}
func TestIntegrationPasswordResetRevokesSessions(t *testing.T) {
	e := integrationEngine(t)
	who, _, email := integrationSession(t, e)
	ctx := testContext(t)
	if err := e.StartPasswordReset(ctx, email, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if err := e.StartPasswordReset(ctx, "unknown@example.test", ""); !errors.Is(err, ErrUnavailable) {
		t.Fatal("misconfiguration leaks account existence", err)
	}
	if err := e.StartPasswordReset(ctx, email, "https://example.test/reset"); err != nil {
		t.Fatal(err)
	}
	token := mailToken(t, e, email, "password_reset")
	if err := e.ConfirmPasswordReset(ctx, token, "changed-password"); err != nil {
		t.Fatal(err)
	}
	if err := e.ValidateSession(ctx, who); !errors.Is(err, ErrSession) {
		t.Fatal("reset kept old session", err)
	}
	if err := e.ConfirmPasswordReset(ctx, token, "other-password"); !errors.Is(err, ErrInvalid) {
		t.Fatal("reset token replay", err)
	}
}

func TestIntegrationDuplicateRegistrationDisclosesOnlyAfterEmailProof(t *testing.T) {
	e := integrationEngine(t)
	_, email := integrationSignup(t, e)
	ctx := testContext(t)
	var previous string
	if err := e.DB.QueryRowContext(ctx, `SELECT password_hash FROM accounts WHERE email=$1`, email).Scan(&previous); err != nil {
		t.Fatal(err)
	}
	process, err := beginRegistration(t, e, email)
	if err != nil {
		t.Fatal("registration disclosed existence before proof", err)
	}
	challenge, err := e.CreateChallenge(ctx, process.ID, process.FlowToken, "email", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Attempt(ctx, process.ID, challenge.ID, process.FlowToken, Principal{}, Proof{Method: "email", Code: "wrong"}); !errors.Is(err, ErrCredentials) {
		t.Fatal("invalid proof disclosed existence", err)
	}
	var code string
	if err = e.DB.QueryRowContext(ctx, `SELECT body->>'code' FROM outbox WHERE body->>'to'=$1 AND body->>'template'='registration_code' ORDER BY creation_timestamp DESC LIMIT 1`, email).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Attempt(ctx, process.ID, challenge.ID, process.FlowToken, Principal{}, Proof{Method: "email", Code: code}); !errors.Is(err, ErrAccountExists) {
		t.Fatal("verified duplicate must offer sign-in/reset", err)
	}
	failed, err := e.Get(ctx, process.ID, process.FlowToken, Principal{})
	if err != nil || failed.Status != "failed" || len(failed.Next.Methods) != 0 || failed.ConfirmationToken != "" {
		t.Fatal("duplicate signup did not terminate", err)
	}
	var current string
	if err = e.DB.QueryRowContext(ctx, `SELECT password_hash FROM accounts WHERE email=$1`, email).Scan(&current); err != nil || current != previous {
		t.Fatal("registration replaced existing password", err)
	}
}
