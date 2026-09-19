package authentication

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/mephistolie/chefbook-backend-common/tokens/access"
)

type integrationIssuer struct{}

func (integrationIssuer) CreateAccess(access.Payload, time.Duration) (string, error) {
	return "test-only-access", nil
}
func integrationEngine(t *testing.T) *Engine {
	t.Helper()
	dsn := os.Getenv("AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTH_TEST_DATABASE_URL unset")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	admin := stdlib.OpenDB(*cfg)
	name := "auth_engine_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	copied := cfg.Copy()
	copied.RuntimeParams["search_path"] = name
	db := stdlib.OpenDB(*copied)
	db.SetMaxOpenConns(8)
	t.Cleanup(func() {
		db.Close()
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(c, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	schema, err := os.ReadFile("../../schema/initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(schema)); err != nil {
		t.Fatal(err)
	}
	secrets, err := NewSecrets(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := New(db, secrets, OutboxMail{})
	e.BcryptCost = 4
	return e
}
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func integrationSignup(t *testing.T, e *Engine) (Process, string) {
	t.Helper()
	ctx := testContext(t)
	email := uuid.NewString() + "@example.test"
	p, err := beginRegistration(t, e, email)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err = e.DB.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE email=$1`, email).Scan(&n); err != nil || n != 0 {
		t.Fatal("account exists before email proof")
	}
	c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "email", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	var code string
	if err = e.DB.QueryRowContext(ctx, `SELECT body->>'code' FROM outbox WHERE type='mail.send.v1' AND body->>'to'=$1`, email).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Attempt(ctx, p.ID, c.ID, "wrong-flow", Principal{}, Proof{Method: "email", Code: code}); err == nil {
		t.Fatal("code accepted outside original flow")
	}
	result, err := e.Attempt(ctx, p.ID, c.ID, p.FlowToken, Principal{}, Proof{Method: "email", Code: code})
	if err != nil {
		t.Fatal(err)
	}
	setup, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "passwordSetup", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = e.Attempt(ctx, p.ID, setup.ID, p.FlowToken, Principal{}, Proof{Method: "passwordSetup", Password: "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Authentication.Status != "completed" || result.Authentication.ConfirmationToken == "" {
		t.Fatal("registration did not complete")
	}
	if _, err = e.Attempt(ctx, p.ID, c.ID, p.FlowToken, Principal{}, Proof{Method: "email", Code: code}); err == nil {
		t.Fatal("email proof replayed")
	}
	return result.Authentication, email
}

func beginRegistration(t *testing.T, e *Engine, email string) (Process, error) {
	t.Helper()
	ctx := testContext(t)
	p, err := e.Start(ctx, StartRequest{Purpose: Purpose{Type: "signUp"}}, Principal{})
	if err != nil {
		return p, err
	}
	c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "registration", Principal{})
	if err != nil {
		return p, err
	}
	_, err = e.Attempt(ctx, p.ID, c.ID, p.FlowToken, Principal{}, Proof{Method: "registration", Email: email})
	return p, err
}
func integrationSession(t *testing.T, e *Engine) (Principal, Tokens, string) {
	t.Helper()
	p, email := integrationSignup(t, e)
	tokens, err := e.CreateSession(testContext(t), p.ConfirmationToken, "127.0.0.1", "test", integrationIssuer{}, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return Principal{AccountID: tokens.UserID, SessionID: tokens.SessionID}, tokens, email
}
func provePassword(t *testing.T, e *Engine, purpose string, who Principal, email string) Process {
	t.Helper()
	ctx := testContext(t)
	p, err := e.Start(ctx, StartRequest{Purpose: Purpose{Type: purpose}}, who)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status == "completed" {
		return p
	}
	c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "password", who)
	if err != nil {
		t.Fatal(err)
	}
	login := email
	if sensitive(purpose) {
		login = ""
	}
	result, err := e.Attempt(ctx, p.ID, c.ID, p.FlowToken, who, Proof{Method: "password", Login: login, Password: "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	result.Authentication.FlowToken = p.FlowToken
	return result.Authentication
}
func raceTwo(t *testing.T, f func() error) {
	t.Helper()
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs <- f() }()
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly one commit, got %d", success)
	}
}
func TestIntegrationGrantAndRefreshSingleUse(t *testing.T) {
	e := integrationEngine(t)
	p, _ := integrationSignup(t, e)
	ctx := testContext(t)
	var mu sync.Mutex
	var tokens Tokens
	raceTwo(t, func() error {
		v, err := e.CreateSession(ctx, p.ConfirmationToken, "127.0.0.1", "test", integrationIssuer{}, time.Minute, time.Hour)
		if err == nil {
			mu.Lock()
			tokens = v
			mu.Unlock()
		}
		return err
	})
	raceTwo(t, func() error {
		_, err := e.Refresh(ctx, tokens.SessionID, tokens.RefreshToken, "127.0.0.1", "test", integrationIssuer{}, time.Minute, time.Hour)
		return err
	})
}
func TestIntegrationReauthenticationDoesNotSlideAndRevokes(t *testing.T) {
	e := integrationEngine(t)
	who, _, email := integrationSession(t, e)
	now := time.Now()
	e.Now = func() time.Time { return now }
	original := provePassword(t, e, "passwordChange", who, email)
	if original.Status != "completed" {
		t.Fatal("reauth incomplete")
	}
	now = now.Add(4 * time.Minute)
	derived, err := e.Start(testContext(t), StartRequest{Purpose: Purpose{Type: "emailChange"}}, who)
	if err != nil || derived.Status != "completed" {
		t.Fatalf("fresh proof not reused: %v", err)
	}
	now = now.Add(2 * time.Minute)
	expired, err := e.Start(testContext(t), StartRequest{Purpose: Purpose{Type: "accountDeletion"}}, who)
	if err != nil || expired.Status != "pending" {
		t.Fatalf("derived completion extended trust: %v", err)
	}
	if err = e.RevokeSessions(testContext(t), who, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Start(testContext(t), StartRequest{Purpose: Purpose{Type: "passwordChange"}}, who); err == nil {
		t.Fatal("revoked session authorized a new process")
	}
}
func otp(secret []byte, now time.Time) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(now.Unix()/30))
	h := hmac.New(sha1.New, secret)
	h.Write(b[:])
	v := h.Sum(nil)
	offset := v[len(v)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(v[offset:offset+4])&0x7fffffff)%1000000)
}
func TestIntegrationTOTPAndBackupReplay(t *testing.T) {
	e := integrationEngine(t)
	who, _, email := integrationSession(t, e)
	now := time.Now()
	e.Now = func() time.Time { return now }
	proof := provePassword(t, e, "totpEnrollment", who, email)
	setup, err := e.StartTotp(testContext(t), who, proof.ConfirmationToken)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := otp(secret, now)
	codes, err := e.ConfirmTotp(testContext(t), who, code)
	if err != nil {
		t.Fatal(err)
	}
	first := provePassword(t, e, "signIn", Principal{}, email)
	c, err := e.CreateChallenge(testContext(t), first.ID, first.FlowToken, "totp", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Attempt(testContext(t), first.ID, c.ID, first.FlowToken, Principal{}, Proof{Method: "totp", Code: code}); err == nil {
		t.Fatal("activation TOTP reused for login")
	}
	second := provePassword(t, e, "signIn", Principal{}, email)
	processes := []Process{first, second}
	challenges := make([]Challenge, 2)
	for i, p := range processes {
		challenges[i], err = e.CreateChallenge(testContext(t), p.ID, p.FlowToken, "backupCode", Principal{})
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx := testContext(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, p := range processes {
		go func(p Process, c Challenge) {
			<-start
			_, err := e.Attempt(ctx, p.ID, c.ID, p.FlowToken, Principal{}, Proof{Method: "backupCode", Code: codes.Codes[0]})
			results <- err
		}(p, challenges[i])
	}
	close(start)
	success := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("backup code used %d times", success)
	}
}

func TestIntegrationEmailAttemptBudgetSurvivesResend(t *testing.T) {
	e := integrationEngine(t)
	e.MaxAttempts = 2
	ctx := testContext(t)
	p, err := beginRegistration(t, e, "attempts@example.test")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "email", Principal{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.Attempt(ctx, p.ID, c.ID, p.FlowToken, Principal{}, Proof{Method: "email", Code: "not-a-code"})
		expected := ErrCredentials
		if i == 1 {
			expected = ErrAttempts
		}
		if err != expected {
			t.Fatalf("attempt %d expected %v, got %v", i, expected, err)
		}
	}
	if _, err = e.CreateChallenge(ctx, p.ID, p.FlowToken, "email", Principal{}); err == nil {
		t.Fatal("resend bypassed exhausted authentication budget")
	}
	var count int
	var status string
	if err = e.DB.QueryRowContext(ctx, `SELECT failed_attempts,status FROM authentications WHERE authentication_id=$1`, p.ID).Scan(&count, &status); err != nil || count != 2 || status != "failed" {
		t.Fatal("attempt budget not durable")
	}
}

type failingIntegrationMail struct{}

func (failingIntegrationMail) QueueCode(ctx context.Context, tx *sql.Tx, email, code string, expiry time.Time) error {
	if err := (OutboxMail{}).QueueCode(ctx, tx, email, code, expiry); err != nil {
		return err
	}
	return fmt.Errorf("test rollback")
}
func TestIntegrationEmailAndChallengeRollbackTogether(t *testing.T) {
	e := integrationEngine(t)
	e.Mail = failingIntegrationMail{}
	ctx := testContext(t)
	p, err := beginRegistration(t, e, "rollback@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.CreateChallenge(ctx, p.ID, p.FlowToken, "email", Principal{}); err == nil {
		t.Fatal("failed enqueue accepted")
	}
	for _, table := range []string{"email_authentication_steps", "outbox"} {
		var n int
		if err = e.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("rollback left rows in %s", table)
		}
	}
}
