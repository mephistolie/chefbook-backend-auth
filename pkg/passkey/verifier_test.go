package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"testing"
	"time"
)

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func fixture(t *testing.T) (*Verifier, Account, *ecdsa.PrivateKey) {
	t.Helper()
	v, e := New(Config{RPID: "chefbook.io", Origins: []string{"https://chefbook.io"}})
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if e != nil {
		t.Fatal(e)
	}
	a := Account{ID: uuid.New(), Name: "test", Credentials: []Credential{{ID: []byte("credential-id"), PublicKey: pk, SignCount: 1}}}
	return v, a, key
}
func assertion(t *testing.T, a Account, key *ecdsa.PrivateKey, challenge []byte, origin, rp string, flags byte, count uint32) []byte {
	t.Helper()
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": enc(challenge), "origin": origin})
	rpHash := sha256.Sum256([]byte(rp))
	auth := append([]byte(nil), rpHash[:]...)
	auth = append(auth, flags)
	auth = binary.BigEndian.AppendUint32(auth, count)
	hash := sha256.Sum256(client)
	signed := append(append([]byte(nil), auth...), hash[:]...)
	digest := sha256.Sum256(signed)
	sig, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	response, _ := json.Marshal(map[string]any{"id": enc(a.Credentials[0].ID), "rawId": enc(a.Credentials[0].ID), "type": "public-key", "response": map[string]string{"clientDataJSON": enc(client), "authenticatorData": enc(auth), "signature": enc(sig), "userHandle": enc(a.WebAuthnID())}})
	return response
}
func TestAssertionVerification(t *testing.T) {
	v, a, key := fixture(t)
	expiry := time.Now().Add(time.Minute)
	begin, e := v.BeginAuthentication(expiry)
	if e != nil {
		t.Fatal(e)
	}
	valid := assertion(t, a, key, begin.Challenge, "https://chefbook.io", "chefbook.io", 5, 2)
	updated, e := v.VerifyAuthentication(a, begin.Challenge, expiry, valid)
	if e != nil || updated.SignCount != 2 {
		t.Fatalf("valid assertion rejected: %v", e)
	}
	for _, tc := range []struct {
		name, origin, rp string
		flags            byte
		count            uint32
	}{{"origin", "https://evil.example", "chefbook.io", 5, 2}, {"rp", "https://chefbook.io", "evil.example", 5, 2}, {"UV", "https://chefbook.io", "chefbook.io", 1, 2}, {"UP", "https://chefbook.io", "chefbook.io", 4, 2}, {"counter", "https://chefbook.io", "chefbook.io", 5, 1}, {"backup mismatch", "https://chefbook.io", "chefbook.io", 13, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.VerifyAuthentication(a, begin.Challenge, expiry, assertion(t, a, key, begin.Challenge, tc.origin, tc.rp, tc.flags, tc.count)); err == nil {
				t.Fatal("invalid assertion accepted")
			}
		})
	}
	wrong := append([]byte(nil), begin.Challenge...)
	wrong[0] ^= 1
	if _, e = v.VerifyAuthentication(a, wrong, expiry, valid); e == nil {
		t.Fatal("wrong challenge accepted")
	}
	other := a
	other.ID = uuid.New()
	if _, e = v.VerifyAuthentication(other, begin.Challenge, expiry, valid); e == nil {
		t.Fatal("wrong user handle accepted")
	}
	if _, e = v.VerifyAuthentication(a, begin.Challenge, time.Now().Add(-time.Second), valid); e == nil {
		t.Fatal("expired challenge accepted")
	}
	_, _, differentKey := fixture(t)
	if _, e = v.VerifyAuthentication(a, begin.Challenge, expiry, assertion(t, a, differentKey, begin.Challenge, "https://chefbook.io", "chefbook.io", 5, 2)); e == nil {
		t.Fatal("wrong signature accepted")
	}
}
func TestSyncedZeroCounters(t *testing.T) {
	v, a, key := fixture(t)
	a.Credentials[0].SignCount = 0
	a.Credentials[0].BackupEligible = true
	expiry := time.Now().Add(time.Minute)
	b, _ := v.BeginAuthentication(expiry)
	c, e := v.VerifyAuthentication(a, b.Challenge, expiry, assertion(t, a, key, b.Challenge, "https://chefbook.io", "chefbook.io", 29, 0))
	if e != nil || !c.BackupState {
		t.Fatalf("synced passkey failed: %v", e)
	}
}
func TestRegistrationNoneAttestation(t *testing.T) {
	v, a, _ := fixture(t)
	credential := a.Credentials[0]
	a.Credentials = nil
	expiry := time.Now().Add(time.Minute)
	b, e := v.BeginRegistration(a, expiry)
	if e != nil {
		t.Fatal(e)
	}
	client, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": enc(b.Challenge), "origin": "https://chefbook.io"})
	rpHash := sha256.Sum256([]byte("chefbook.io"))
	auth := append([]byte(nil), rpHash[:]...)
	auth = append(auth, 69)
	auth = binary.BigEndian.AppendUint32(auth, 0)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(credential.ID)))
	auth = append(auth, credential.ID...)
	auth = append(auth, credential.PublicKey...)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "authData": auth, "attStmt": map[string]any{}})
	raw, _ := json.Marshal(map[string]any{"id": enc(credential.ID), "rawId": enc(credential.ID), "type": "public-key", "response": map[string]any{"clientDataJSON": enc(client), "attestationObject": enc(att), "transports": []string{"internal"}}})
	c, e := v.VerifyRegistration(a, b.Challenge, expiry, raw)
	if e != nil || string(c.ID) != string(credential.ID) {
		t.Fatalf("registration failed: %v", e)
	}
	a.Credentials = []Credential{c}
	if _, e = v.VerifyRegistration(a, b.Challenge, expiry, raw); e == nil {
		t.Fatal("duplicate credential accepted")
	}
}
