package authentication

import (
	"bytes"
	"testing"
	"time"
)

func TestTOTPRFC6238AndReplayRejection(t *testing.T) {
	// RFC 6238 appendix B SHA-1 vectors, truncated to the configured six digits.
	secret := []byte("12345678901234567890")
	for _, test := range []struct {
		timestamp int64
		code      string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		at := time.Unix(test.timestamp, 0)
		step, ok := totpStep(secret, test.code, at, -1)
		if !ok || step != test.timestamp/30 {
			t.Fatalf("known vector rejected at %d", test.timestamp)
		}
		if _, ok = totpStep(secret, test.code, at, step); ok {
			t.Fatal("already consumed moving factor accepted")
		}
	}
	if _, ok := totpStep(secret, "94287082", time.Unix(59, 0), -1); ok {
		t.Fatal("wrong code length accepted")
	}
	if _, ok := totpStep(secret, "abcdef", time.Unix(59, 0), -1); ok {
		t.Fatal("nonnumeric code accepted")
	}
}
func TestProofHashesSeparatePurposeAndAccount(t *testing.T) {
	s, err := NewSecrets(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reference := s.Hash("email", "account-one", "same-proof")
	for _, sum := range [][]byte{s.Hash("backup", "account-one", "same-proof"), s.Hash("email", "account-two", "same-proof"), s.Hash("email", "account-one", "different-proof")} {
		if bytes.Equal(reference, sum) {
			t.Fatal("proof scopes collide")
		}
	}
	if !bytes.Equal(reference, s.Hash("email", "account-one", "same-proof")) {
		t.Fatal("proof hashing is unstable")
	}
}
func TestEncryptedSecretBoundToAccount(t *testing.T) {
	s, err := NewSecrets(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("test-secret")
	ciphertext, err := s.Encrypt(value, "account-one")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.Decrypt(ciphertext, "account-one")
	if err != nil || !bytes.Equal(plain, value) {
		t.Fatal("valid secret failed")
	}
	if _, err = s.Decrypt(ciphertext, "account-two"); err == nil {
		t.Fatal("cross-account ciphertext accepted")
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err = s.Decrypt(ciphertext, "account-one"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err = s.Decrypt([]byte{1}, "account-one"); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
}
