package provider

import (
	"context"
	"errors"
	engine "github.com/mephistolie/chefbook-backend-auth/internal/authentication"
	"net/url"
	"strings"
	"testing"
)

func TestGoogleAuthorizationBinding(t *testing.T) {
	g := Google{ClientID: "test-client"}
	link, err := g.Authorize("state", "server-nonce", "pkce-challenge", "https://chefbook.io/callback", true)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"state": "state", "nonce": "server-nonce", "code_challenge": "pkce-challenge", "code_challenge_method": "S256", "max_age": "0", "redirect_uri": "https://chefbook.io/callback"} {
		if u.Query().Get(k) != v {
			t.Fatalf("missing binding %s", k)
		}
	}
}
func TestUnavailableNativeAndEmptyGoogleProof(t *testing.T) {
	if _, err := (VK{}).Native(context.Background(), "not-an-id-token"); err != engine.ErrUnavailable {
		t.Fatal(err)
	}
	if _, err := (Google{ClientID: "test-client"}).Native(context.Background(), ""); err != engine.ErrCredentials {
		t.Fatal(err)
	}
}
func TestProviderErrorsDoNotExposeSecrets(t *testing.T) {
	for _, err := range []error{errors.New("recipient@example.test secret_token"), context.DeadlineExceeded, context.Canceled} {
		safe := providerError(err)
		if safe != engine.ErrUnavailable && safe != engine.ErrCredentials {
			t.Fatal("unknown public error")
		}
		if strings.Contains(safe.Error(), "secret") || strings.Contains(safe.Error(), "recipient") {
			t.Fatal("provider error leaked details")
		}
	}
}
