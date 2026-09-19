package authentication

import (
	"context"
	"github.com/google/uuid"
	"net/url"
	"testing"
	"time"
)

type integrationProvider struct {
	identity    ProviderIdentity
	exchangeErr error
	calls       int
	nonce       string
	reauth      bool
}

func (p *integrationProvider) Authorize(state, nonce, challenge, redirect string, reauth bool) (string, error) {
	p.nonce = nonce
	p.reauth = reauth
	return "https://provider.example.test/authorize?" + url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {challenge}, "redirect_uri": {redirect}}.Encode(), nil
}
func (p *integrationProvider) Exchange(context.Context, string, string, string) (ProviderIdentity, error) {
	p.calls++
	v := p.identity
	if v.Nonce == "" {
		v.Nonce = p.nonce
	}
	return v, p.exchangeErr
}
func (p *integrationProvider) Native(context.Context, string) (ProviderIdentity, error) {
	p.calls++
	return p.identity, p.exchangeErr
}
func oauthFixture(t *testing.T) (*Engine, Principal, string, *integrationProvider) {
	t.Helper()
	e := integrationEngine(t)
	who, _, email := integrationSession(t, e)
	p := &integrationProvider{identity: ProviderIdentity{Subject: "google-subject", Email: email, AuthenticatedAt: time.Now()}}
	e.Providers = map[string]Provider{"google": p, "vk": p}
	e.OAuthRedirects = []string{"https://chefbook.io/oauth/callback"}
	return e, who, email, p
}
func oauthBegin(t *testing.T, e *Engine, purpose, provider string, who Principal) (Process, Challenge, string) {
	t.Helper()
	ctx := testContext(t)
	p, err := e.Start(ctx, StartRequest{Purpose: Purpose{Type: purpose}}, who)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, provider, who, OAuthOptions{CredentialType: "authorizationCode", RedirectURI: e.OAuthRedirects[0]})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		t.Fatal(err)
	}
	return p, c, u.Query().Get("state")
}
func addIdentity(t *testing.T, e *Engine, who Principal, provider, subject string) {
	t.Helper()
	if _, err := e.DB.ExecContext(testContext(t), `INSERT INTO identities(account_id,provider,subject) VALUES($1,$2,$3)`, who.AccountID, provider, subject); err != nil {
		t.Fatal(err)
	}
}
func TestIntegrationOAuthBindingAndSingleUse(t *testing.T) {
	e, who, _, adapter := oauthFixture(t)
	addIdentity(t, e, who, "google", adapter.identity.Subject)
	p, c, state := oauthBegin(t, e, "signIn", "google", Principal{})
	proof := Proof{Method: "google", Code: "provider-code", State: state}
	ctx := testContext(t)
	if _, err := e.AttemptProvider(ctx, p.ID, c.ID, "wrong-flow", Principal{}, proof); err == nil || adapter.calls != 0 {
		t.Fatal("wrong flow reached provider")
	}
	result, err := e.AttemptProvider(ctx, p.ID, c.ID, p.FlowToken, Principal{}, proof)
	if err != nil || result.Authentication.Status != "completed" {
		t.Fatalf("correct flow failed: %v", err)
	}
	if _, err = e.AttemptProvider(ctx, p.ID, c.ID, p.FlowToken, Principal{}, proof); err == nil || adapter.calls != 1 {
		t.Fatal("OAuth state replay reached provider")
	}
}
func TestIntegrationOAuthStateConsumedBeforeNetworkFailure(t *testing.T) {
	e, _, _, adapter := oauthFixture(t)
	adapter.exchangeErr = ErrUnavailable
	p, c, state := oauthBegin(t, e, "signIn", "google", Principal{})
	proof := Proof{Method: "google", Code: "provider-code", State: state}
	ctx := testContext(t)
	if _, err := e.AttemptProvider(ctx, p.ID, c.ID, p.FlowToken, Principal{}, proof); err != ErrUnavailable {
		t.Fatal(err)
	}
	var n int
	if err := e.DB.QueryRowContext(ctx, `SELECT count(*) FROM oauth_requests WHERE state_hash=$1`, e.Secrets.Hash("state", "", state)).Scan(&n); err != nil || n != 0 {
		t.Fatal("state survived failed exchange")
	}
	if _, err := e.AttemptProvider(ctx, p.ID, c.ID, p.FlowToken, Principal{}, proof); err == nil || adapter.calls != 1 {
		t.Fatal("failed exchange state reused")
	}
}
func TestIntegrationNativeNonceAndNoEmailAutolink(t *testing.T) {
	e, who, _, adapter := oauthFixture(t)
	ctx := testContext(t)
	p, err := e.Start(ctx, StartRequest{Purpose: Purpose{Type: "signIn"}}, Principal{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "google", Principal{}, OAuthOptions{CredentialType: "idToken"})
	if err != nil {
		t.Fatal(err)
	}
	adapter.identity.Nonce = "incorrect"
	proof := Proof{Method: "google", IDToken: "signed-by-fake-provider"}
	if _, err = e.AttemptProvider(ctx, p.ID, c.ID, p.FlowToken, Principal{}, proof); err != ErrCredentials {
		t.Fatalf("nonce mismatch accepted: %v", err)
	}
	adapter.identity.Nonce = c.Nonce
	if _, err = e.AttemptProvider(ctx, p.ID, c.ID, p.FlowToken, Principal{}, proof); err != ErrCredentials {
		t.Fatalf("same email auto-linked identity: %v", err)
	}
	addIdentity(t, e, who, "google", adapter.identity.Subject)
	if _, err = e.AttemptProvider(ctx, p.ID, c.ID, p.FlowToken, Principal{}, proof); err != nil {
		t.Fatalf("valid bound native proof rejected: %v", err)
	}
}
func TestIntegrationProviderFreshnessRequired(t *testing.T) {
	for _, tc := range []struct {
		name, provider string
		at             time.Time
	}{{"missing-google", "google", time.Time{}}, {"stale-google", "google", time.Now().Add(-time.Hour)}, {"missing-vk", "vk", time.Time{}}} {
		t.Run(tc.name, func(t *testing.T) {
			e, who, _, adapter := oauthFixture(t)
			adapter.identity.AuthenticatedAt = tc.at
			addIdentity(t, e, who, tc.provider, adapter.identity.Subject)
			p, c, state := oauthBegin(t, e, "passwordChange", tc.provider, who)
			if !adapter.reauth {
				t.Fatal("reauth policy not passed to provider")
			}
			if _, err := e.AttemptProvider(testContext(t), p.ID, c.ID, p.FlowToken, who, Proof{Method: tc.provider, Code: "code", State: state}); err != ErrForbidden {
				t.Fatalf("missing/stale provider auth time accepted: %v", err)
			}
		})
	}
}
func TestIntegrationProviderSignupNotAllowed(t *testing.T) {
	e, _, _, adapter := oauthFixture(t)
	ctx := testContext(t)
	email := uuid.NewString() + "@example.test"
	adapter.identity.Email = "different-provider-email@example.test"
	adapter.identity.Subject = "new-provider-subject"
	p, err := beginRegistration(t, e, email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.CreateChallenge(ctx, p.ID, p.FlowToken, "google", Principal{}, OAuthOptions{CredentialType: "idToken"}); err == nil {
		t.Fatal("provider bypassed required email step")
	}
	c, err := e.CreateChallenge(ctx, p.ID, p.FlowToken, "email", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	var code string
	if err = e.DB.QueryRowContext(ctx, `SELECT body->>'code' FROM outbox WHERE body->>'to'=$1`, email).Scan(&code); err != nil {
		t.Fatal(err)
	}
	result, err := e.Attempt(ctx, p.ID, c.ID, p.FlowToken, Principal{}, Proof{Method: "email", Code: code})
	if err != nil || result.Authentication.Status != "pending" || result.Authentication.ConfirmationToken != "" {
		t.Fatalf("signup completed without password: %v", err)
	}
	var count int
	if err = e.DB.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE email=$1`, email).Scan(&count); err != nil || count != 0 {
		t.Fatal("account created before both proofs")
	}
	for _, method := range []string{"google", "vk"} {
		if _, err = e.CreateChallenge(ctx, p.ID, p.FlowToken, method, Principal{}, OAuthOptions{CredentialType: "idToken"}); err != ErrForbidden {
			t.Fatalf("provider signup allowed after email proof: %v", err)
		}
	}
	if len(result.Authentication.Next.Methods) != 1 || result.Authentication.Next.Methods[0] != "passwordSetup" {
		t.Fatal("signup must only offer password setup after email proof")
	}

}
func TestIntegrationIdentityOAuthBoundToSession(t *testing.T) {
	e, who, email, adapter := oauthFixture(t)
	ctx := testContext(t)
	prepared, err := e.PrepareIdentityOAuth(ctx, who, "google", e.OAuthRedirects[0])
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(prepared.URL)
	state := u.Query().Get("state")
	otherLogin := provePassword(t, e, "signIn", Principal{}, email)
	token, err := e.CreateSession(ctx, otherLogin.ConfirmationToken, "127.0.0.1", "other", integrationIssuer{}, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other := Principal{AccountID: who.AccountID, SessionID: token.SessionID}
	grant := provePassword(t, e, "identityLink", who, email)
	if _, err = e.LinkIdentity(ctx, other, grant.ConfirmationToken, "google", "code", state); err == nil || adapter.calls != 0 {
		t.Fatal("wrong session consumed identity state")
	}
	if created, err := e.LinkIdentity(ctx, who, grant.ConfirmationToken, "google", "code", state); err != nil || !created {
		t.Fatalf("bound identity link failed: %v", err)
	}
	unlink := provePassword(t, e, "identityUnlink", who, email)
	if err = e.UnlinkIdentity(ctx, who, unlink.ConfirmationToken, "google"); err != nil {
		t.Fatal(err)
	}
	identities, err := e.GetIdentities(ctx, who)
	if err != nil || len(identities) != 0 {
		t.Fatal("identity not removed")
	}
}
