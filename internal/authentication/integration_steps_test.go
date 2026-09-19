package authentication

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	key "github.com/mephistolie/chefbook-backend-auth/pkg/passkey"
)

func verifiedRegistration(t *testing.T, e *Engine, email string) Process {
	t.Helper()
	ctx := testContext(t)
	p, err := beginRegistration(t, e, email)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "email", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	var code string
	err = e.DB.QueryRowContext(ctx, `SELECT body->>'code' FROM outbox WHERE body->>'to'=$1 ORDER BY creation_timestamp DESC LIMIT 1`, email).Scan(&code)
	if err != nil {
		t.Fatal(err)
	}
	done, err := e.Attempt(ctx, p.ID, c.ID, p.FlowToken, Principal{}, Proof{Method: "email", Code: code})
	if err != nil {
		t.Fatal(err)
	}
	done.Authentication.FlowToken = p.FlowToken
	return done.Authentication
}

func TestIntegrationRegistrationPrerequisitesAndPrivacy(t *testing.T) {
	e := integrationEngine(t)
	ctx := testContext(t)
	_, taken := integrationSignup(t, e)
	for _, email := range []string{taken, "unregistered@example.test"} {
		p, err := e.Start(ctx, StartRequest{Purpose: Purpose{Type: "signUp"}}, Principal{})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p.Next.Methods, []string{"registration"}) {
			t.Fatal("start disclosed account or selected credential")
		}
		var count int
		if err = e.DB.QueryRowContext(ctx, `SELECT count(*) FROM registrations WHERE authentication_id=$1`, p.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("start prematurely collected registration")
		}
		for _, m := range []string{"passwordSetup", "email", "passkeyRegistration", "google"} {
			if _, err = e.CreateChallenge(ctx, p.ID, p.FlowToken, m, Principal{}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("early %s: %v", m, err)
			}
		}
		r, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "registration", Principal{})
		if err != nil {
			t.Fatal(err)
		}
		done, err := e.Attempt(ctx, p.ID, r.ID, p.FlowToken, Principal{}, Proof{Method: "registration", Email: email})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(done.Authentication.Next.Methods, []string{"email"}) {
			t.Fatal("email existence affected public options")
		}
		if _, err = e.CreateChallenge(ctx, p.ID, p.FlowToken, "passwordSetup", Principal{}); !errors.Is(err, ErrForbidden) {
			t.Fatal("password setup before email", err)
		}
		// Defense in depth: completion rechecks prerequisites even for an injected step.
		injected := uuid.New()
		if _, err = e.DB.ExecContext(ctx, `INSERT INTO authentication_steps(step_id,authentication_id,type,expiration_timestamp) VALUES($1,$2,'passwordSetup',$3)`, injected, p.ID, p.ExpirationTimestamp); err != nil {
			t.Fatal(err)
		}
		if _, err = e.Attempt(ctx, p.ID, injected, p.FlowToken, Principal{}, Proof{Method: "passwordSetup", Password: "valid-password"}); !errors.Is(err, ErrForbidden) {
			t.Fatal("completion skipped proof", err)
		}
		var hasPassword bool
		if err = e.DB.QueryRowContext(ctx, `SELECT password_hash IS NOT NULL FROM registrations WHERE authentication_id=$1`, p.ID).Scan(&hasPassword); err != nil || hasPassword {
			t.Fatal("unverified password persisted")
		}
		if _, err = e.Attempt(ctx, p.ID, r.ID, p.FlowToken, Principal{}, Proof{Method: "registration", Email: "replacement@example.test"}); !errors.Is(err, ErrConflict) {
			t.Fatal("accepted email changed", err)
		}
	}
}

func TestIntegrationRegistrationSameEmailFinalizationRace(t *testing.T) {
	e := integrationEngine(t)
	ctx := testContext(t)
	email := "race@example.test"
	a := verifiedRegistration(t, e, email)
	b := verifiedRegistration(t, e, email)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, p := range []Process{a, b} {
		c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "passwordSetup", Principal{})
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(p Process, c Challenge) {
			defer wg.Done()
			<-start
			_, err := e.Attempt(ctx, p.ID, c.ID, p.FlowToken, Principal{}, Proof{Method: "passwordSetup", Password: "new-password"})
			results <- err
		}(p, c)
	}
	close(start)
	wg.Wait()
	close(results)
	success, exists := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrAccountExists) {
			exists++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || exists != 1 {
		t.Fatalf("race outcomes %d/%d", success, exists)
	}
	var accounts, events, grants, failed int
	if err := e.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM accounts WHERE email=$1),(SELECT count(*) FROM outbox WHERE type='profile.created'),(SELECT count(*) FROM authentications WHERE confirmation_token_hash IS NOT NULL),(SELECT count(*) FROM authentications WHERE status='failed')`, email).Scan(&accounts, &events, &grants, &failed); err != nil {
		t.Fatal(err)
	}
	if accounts != 1 || events != 1 || grants != 1 || failed != 1 {
		t.Fatalf("non-atomic finalization %d/%d/%d/%d", accounts, events, grants, failed)
	}
}

func TestIntegrationEmailResendKeepsFlowBudgetAndRejectsStaleStep(t *testing.T) {
	e := integrationEngine(t)
	ctx := testContext(t)
	now := time.Now()
	e.Now = func() time.Time { return now }
	p, err := beginRegistration(t, e, "resend@example.test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "email", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	var oldCode string
	if err = e.DB.QueryRowContext(ctx, `SELECT body->>'code' FROM outbox WHERE body->>'to'='resend@example.test'`).Scan(&oldCode); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Attempt(ctx, p.ID, first.ID, p.FlowToken, Principal{}, Proof{Method: "email", Code: "wrong"}); !errors.Is(err, ErrCredentials) {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	second, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "email", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Attempt(ctx, p.ID, first.ID, p.FlowToken, Principal{}, Proof{Method: "email", Code: oldCode}); !errors.Is(err, ErrConflict) {
		t.Fatal("old emailed code accepted", err)
	}
	var count int
	var expiry time.Time
	if err = e.DB.QueryRowContext(ctx, `SELECT failed_attempts,expiration_timestamp FROM authentications WHERE authentication_id=$1`, p.ID).Scan(&count, &expiry); err != nil || count != 1 || expiry.Sub(p.ExpirationTimestamp) > time.Microsecond {
		t.Fatal("resend reset flow", err)
	}
	other, err := beginRegistration(t, e, "other@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.GetChallenge(ctx, other.ID, second.ID, other.FlowToken, Principal{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("foreign nested step readable", err)
	}
	now = now.Add(6 * time.Minute)
	if _, err = e.Attempt(ctx, p.ID, second.ID, p.FlowToken, Principal{}, Proof{Method: "email", Code: "000000"}); !errors.Is(err, ErrConflict) {
		t.Fatal("expired step accepted", err)
	}
}

func TestIntegrationRegistrationCancelsCredentialAlternatives(t *testing.T) {
	e := integrationEngine(t)
	ctx := testContext(t)
	e.Passkeys, _ = key.New(key.Config{RPID: "chefbook.io", Origins: []string{"https://chefbook.io"}})
	p := verifiedRegistration(t, e, "alternatives@example.test")
	stale, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "passwordSetup", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"passkeyRegistration", "google", "vk", "passkey"} {
		if _, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, method, Principal{}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("signup offered non-password credential %s: %v", method, err)
		}
	}
	password, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "passwordSetup", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.Attempt(ctx, p.ID, password.ID, p.FlowToken, Principal{}, Proof{Method: "passwordSetup", Password: "new-password"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Authentication.Steps) != 4 {
		t.Fatal("missing step history")
	}
	if _, err = e.Attempt(ctx, p.ID, stale.ID, p.FlowToken, Principal{}, Proof{Method: "passwordSetup", Password: "stale-password"}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale alternative accepted", err)
	}
	for _, step := range result.Authentication.Steps {
		if step.ID == stale.ID && step.Status != "cancelled" {
			t.Fatal("stale password step was not cancelled")
		}
	}
	read, err := e.Get(ctx, p.ID, p.FlowToken, Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if read.ConfirmationToken != "" || read.FlowToken != "" {
		t.Fatal("GET exposed token")
	}
	if _, err = e.Attempt(ctx, p.ID, password.ID, p.FlowToken, Principal{}, Proof{Method: "passwordSetup", Password: "other-password"}); !errors.Is(err, ErrConflict) {
		t.Fatal("final completion replayed", err)
	}
	tokens, err := e.CreateSession(ctx, result.Authentication.ConfirmationToken, "127.0.0.1", "test", integrationIssuer{}, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Even attaching the signup to this session cannot turn setup into reauth evidence.
	if _, err = e.DB.ExecContext(ctx, `UPDATE authentications SET session_id=$2 WHERE authentication_id=$1`, p.ID, tokens.SessionID); err != nil {
		t.Fatal(err)
	}
	fresh, err := e.Start(ctx, StartRequest{Purpose: Purpose{Type: "emailChange"}}, Principal{AccountID: tokens.UserID, SessionID: tokens.SessionID})
	if err != nil || fresh.Status != "pending" {
		t.Fatal("setup reused as identity proof", err)
	}
}
