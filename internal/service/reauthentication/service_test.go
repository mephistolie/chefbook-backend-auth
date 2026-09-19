package reauthentication

import (
	"testing"
	"time"
)

func TestFreshAuthenticationRequiresRecentProviderProof(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, tc := range []struct {
		name      string
		timestamp int64
		want      bool
	}{{"missing", 0, false}, {"old", now.Unix() - 301, false}, {"future", now.Unix() + 31, false}, {"recent", now.Unix() - 30, true}, {"allowed clock skew", now.Unix() + 10, true}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := freshAuthentication(tc.timestamp, now); got != tc.want {
				t.Fatalf("fresh=%t", got)
			}
		})
	}
}
