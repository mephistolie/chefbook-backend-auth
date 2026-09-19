package app

import (
	"bytes"
	"encoding/base64"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"testing"
)

func ptr[T any](v T) *T { return &v }
func TestStableSecretConfigurationFailsClosed(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for _, tc := range []struct {
		name, mac, cipher string
		ok                bool
	}{
		{"missing", "", "", false}, {"bad encoding", "!", valid, false}, {"short", base64.StdEncoding.EncodeToString([]byte("short")), valid, false}, {"valid", valid, valid, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := stableSecrets(config.Security{HMACKey: &tc.mac, EncryptionKey: &tc.cipher})
			if (err == nil) != tc.ok {
				t.Fatalf("valid=%v err=%v", tc.ok, err)
			}
		})
	}
}
func TestProductionCannotGenerateEphemeralSigningKey(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	cfg := &config.Config{Environment: ptr(config.EnvProd), Security: config.Security{HMACKey: &key, EncryptionKey: &key}, Auth: config.Auth{AccessTokenSigningKey: ptr(""), SaltCost: ptr(10)}}
	if _, _, err := configureEngine(nil, cfg); err == nil {
		t.Fatal("production accepted no stable signing key")
	}
}
