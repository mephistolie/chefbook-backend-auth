// Package passkey verifies ceremonies using go-webauthn. All challenge and expiry
// arguments must come from server storage, never from a submitted client body.
package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"time"
)

var ErrInvalid = errors.New("invalid passkey ceremony")

type Config struct {
	RPID                   string
	Origins, OpaqueOrigins []string
}
type Verifier struct{ web *webauthn.WebAuthn }
type Account struct {
	ID          uuid.UUID
	Name        string
	Credentials []Credential
}
type Credential struct {
	ID, PublicKey               []byte
	SignCount                   uint32
	BackupEligible, BackupState bool
	Transports                  []string
	CounterWarning              bool
}
type Ceremony struct {
	Challenge []byte
	Options   json.RawMessage
}

// Stored options are pure projections: reading an existing step never generates
// a replacement challenge or extends its expiration. Expired steps remain readable.
func (v *Verifier) AuthenticationOptions(challenge []byte, expires, now time.Time) (json.RawMessage, error) {
	if len(challenge) < 32 {
		return nil, ErrInvalid
	}
	return json.Marshal(protocol.PublicKeyCredentialRequestOptions{
		Challenge: protocol.URLEncodedBase64(challenge), RelyingPartyID: v.web.Config.RPID,
		UserVerification: protocol.VerificationRequired, Timeout: optionTimeout(expires, now),
	})
}
func (v *Verifier) RegistrationOptions(a Account, challenge []byte, expires, now time.Time) (json.RawMessage, error) {
	if a.ID == uuid.Nil || len(challenge) < 32 {
		return nil, ErrInvalid
	}
	return json.Marshal(protocol.PublicKeyCredentialCreationOptions{
		RelyingParty: protocol.RelyingPartyEntity{CredentialEntity: protocol.CredentialEntity{Name: v.web.Config.RPDisplayName}, ID: v.web.Config.RPID},
		User:         protocol.UserEntity{CredentialEntity: protocol.CredentialEntity{Name: a.Name}, DisplayName: a.Name, ID: protocol.URLEncodedBase64(a.WebAuthnID())},
		Challenge:    protocol.URLEncodedBase64(challenge), Parameters: parameters(), Timeout: optionTimeout(expires, now),
		AuthenticatorSelection: v.web.Config.AuthenticatorSelection, Attestation: protocol.PreferNoAttestation,
	})
}
func optionTimeout(expires, now time.Time) int {
	n := expires.Sub(now).Milliseconds()
	if n < 1 {
		return 1
	}
	return int(n)
}

func New(c Config) (*Verifier, error) {
	if c.RPID == "" || len(c.Origins) == 0 {
		return nil, ErrInvalid
	}
	w, err := webauthn.New(&webauthn.Config{RPID: c.RPID, RPDisplayName: "ChefBook", RPOrigins: append([]string(nil), c.Origins...), RPOpaqueOrigins: append([]string(nil), c.OpaqueOrigins...), AttestationPreference: protocol.PreferNoAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}})
	if err != nil {
		return nil, ErrInvalid
	}
	return &Verifier{web: w}, nil
}
func parameters() []protocol.CredentialParameter {
	return []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}, {Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256}}
}
func (v *Verifier) BeginRegistration(a Account, expires time.Time) (Ceremony, error) {
	if a.ID == uuid.Nil || !expires.After(time.Now()) {
		return Ceremony{}, ErrInvalid
	}
	options, session, err := v.web.BeginRegistration(a, webauthn.WithCredentialParameters(parameters()))
	if err != nil {
		return Ceremony{}, ErrInvalid
	}
	return ceremony(session.Challenge, options.Response)
}
func (v *Verifier) BeginAuthentication(expires time.Time) (Ceremony, error) {
	if !expires.After(time.Now()) {
		return Ceremony{}, ErrInvalid
	}
	options, session, err := v.web.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return Ceremony{}, ErrInvalid
	}
	return ceremony(session.Challenge, options.Response)
}
func ceremony(challenge string, options any) (Ceremony, error) {
	b, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		return Ceremony{}, ErrInvalid
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return Ceremony{}, ErrInvalid
	}
	return Ceremony{Challenge: b, Options: raw}, nil
}
func (v *Verifier) session(challenge []byte, expires time.Time) (webauthn.SessionData, error) {
	if len(challenge) < 32 || !expires.After(time.Now()) {
		return webauthn.SessionData{}, ErrInvalid
	}
	return webauthn.SessionData{Challenge: base64.RawURLEncoding.EncodeToString(challenge), RelyingPartyID: v.web.Config.RPID, Expires: expires, UserVerification: protocol.VerificationRequired, CredParams: parameters()}, nil
}
func (v *Verifier) VerifyRegistration(a Account, challenge []byte, expires time.Time, response []byte) (Credential, error) {
	if a.ID == uuid.Nil || len(response) > 65536 {
		return Credential{}, ErrInvalid
	}
	session, err := v.session(challenge, expires)
	if err != nil {
		return Credential{}, err
	}
	session.UserID = a.WebAuthnID()
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	c, err := v.web.CreateCredential(a, session, parsed)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	for _, existing := range a.Credentials {
		if bytes.Equal(existing.ID, c.ID) {
			return Credential{}, ErrInvalid
		}
	}
	return fromLibrary(c), nil
}

// AssertionIdentity returns UNTRUSTED lookup hints. No authentication has happened.
// The caller must load ownership and then call VerifyAuthentication before use.
func AssertionIdentity(response []byte) ([]byte, uuid.UUID, error) {
	if len(response) > 65536 {
		return nil, uuid.Nil, ErrInvalid
	}
	p, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, uuid.Nil, ErrInvalid
	}
	id, err := uuid.FromBytes(p.Response.UserHandle)
	if err != nil || id == uuid.Nil {
		return nil, uuid.Nil, ErrInvalid
	}
	return append([]byte(nil), p.RawID...), id, nil
}
func (v *Verifier) VerifyAuthentication(a Account, challenge []byte, expires time.Time, response []byte) (Credential, error) {
	if a.ID == uuid.Nil || len(response) > 65536 {
		return Credential{}, ErrInvalid
	}
	session, err := v.session(challenge, expires)
	if err != nil {
		return Credential{}, err
	}
	p, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	_, c, err := v.web.ValidatePasskeyLogin(func(id, handle []byte) (webauthn.User, error) {
		if !bytes.Equal(handle, a.WebAuthnID()) {
			return nil, ErrInvalid
		}
		for _, candidate := range a.Credentials {
			if bytes.Equal(candidate.ID, id) {
				return a, nil
			}
		}
		return nil, ErrInvalid
	}, session, p)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	// Synced credentials may have non-monotonic counters. Device-bound nonzero
	// counters indicating a clone are rejected; backup-eligible warnings are returned.
	if c.Authenticator.CloneWarning && !c.Flags.BackupEligible {
		return Credential{}, ErrInvalid
	}
	return fromLibrary(c), nil
}
func (a Account) WebAuthnID() []byte          { return append([]byte(nil), a.ID[:]...) }
func (a Account) WebAuthnName() string        { return a.Name }
func (a Account) WebAuthnDisplayName() string { return a.Name }
func (a Account) WebAuthnCredentials() []webauthn.Credential {
	result := make([]webauthn.Credential, 0, len(a.Credentials))
	for _, c := range a.Credentials {
		flags := protocol.FlagUserPresent | protocol.FlagUserVerified
		if c.BackupEligible {
			flags |= protocol.FlagBackupEligible
		}
		if c.BackupState {
			flags |= protocol.FlagBackupState
		}
		w := webauthn.Credential{ID: append([]byte(nil), c.ID...), PublicKey: append([]byte(nil), c.PublicKey...), Flags: webauthn.NewCredentialFlags(flags), Authenticator: webauthn.Authenticator{SignCount: c.SignCount}}
		for _, t := range c.Transports {
			w.Transport = append(w.Transport, protocol.AuthenticatorTransport(t))
		}
		result = append(result, w)
	}
	return result
}
func fromLibrary(c *webauthn.Credential) Credential {
	r := Credential{ID: append([]byte(nil), c.ID...), PublicKey: append([]byte(nil), c.PublicKey...), SignCount: c.Authenticator.SignCount, BackupEligible: c.Flags.BackupEligible, BackupState: c.Flags.BackupState, CounterWarning: c.Authenticator.CloneWarning}
	for _, t := range c.Transport {
		r.Transports = append(r.Transports, string(t))
	}
	return r
}
