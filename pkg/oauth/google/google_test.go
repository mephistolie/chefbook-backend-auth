package google

import (
	"context"
	"encoding/json"
	"errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestIDTokenClaimsAndProviderFailures(t *testing.T) {
	valid := map[string]string{"sub": "google-user", "aud": "our-client", "iss": "https://accounts.google.com", "exp": strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10), "email": "user@example.com", "email_verified": "true", "auth_time": strconv.FormatInt(time.Now().Unix(), 10)}
	for _, tc := range []struct {
		name, key, value string
		httpCode         int
		network          bool
		want             codes.Code
		accepted         bool
	}{
		{name: "valid", httpCode: 200, accepted: true},
		{name: "wrong audience", key: "aud", value: "attacker-client", httpCode: 200},
		{name: "missing subject", key: "sub", value: "", httpCode: 200},
		{name: "unverified email", key: "email_verified", value: "false", httpCode: 200},
		{name: "wrong issuer", key: "iss", value: "https://attacker.example", httpCode: 200},
		{name: "expired", key: "exp", value: "1", httpCode: 200},
		{name: "provider down", httpCode: 503, want: codes.Unavailable},
		{name: "provider throttled", httpCode: 429, want: codes.Unavailable},
		{name: "network", network: true, want: codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]string{}
			for k, v := range valid {
				claims[k] = v
			}
			if tc.key != "" {
				claims[tc.key] = tc.value
			}
			body, _ := json.Marshal(claims)
			p := NewOAuthProvider("our-client", "secret", "", nil)
			p.client.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Query().Get("id_token") != "opaque+token" {
					t.Error("token query escaping lost")
				}
				if tc.network {
					return nil, errors.New("offline")
				}
				return &http.Response{StatusCode: tc.httpCode, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
			})
			info, err := p.GetUserInfoByIdToken(context.Background(), "opaque+token")
			if tc.accepted {
				if err != nil || info.UserId != "google-user" || info.AuthenticatedAt == 0 {
					t.Fatalf("unexpected identity %v %v", info, err)
				}
			} else if err == nil {
				t.Fatal("invalid token accepted")
			} else if tc.want != codes.OK && status.Code(err) != tc.want {
				t.Fatalf("code=%v", status.Code(err))
			}
		})
	}
}
