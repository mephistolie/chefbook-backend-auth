package authentication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// Secrets requires separately managed keys; no key is persisted with ciphertext.
type Secrets struct {
	macKey []byte
	cipher cipher.AEAD
}

func NewSecrets(macKey, encryptionKey []byte) (Secrets, error) {
	if len(macKey) < 32 || len(encryptionKey) != 32 {
		return Secrets{}, fmt.Errorf("auth keys must be at least 32 / exactly 32 bytes")
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return Secrets{}, err
	}
	aead, err := cipher.NewGCM(block)
	return Secrets{macKey: append([]byte(nil), macKey...), cipher: aead}, err
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n), nil
}
func (s Secrets) Hash(kind, context, value string) []byte {
	h := hmac.New(sha256.New, s.macKey)
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(context))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return h.Sum(nil)
}
func (s Secrets) Encrypt(value []byte, context string) ([]byte, error) {
	nonce := make([]byte, s.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.cipher.Seal(nonce, nonce, value, []byte(context)), nil
}
func (s Secrets) Decrypt(value []byte, context string) ([]byte, error) {
	n := s.cipher.NonceSize()
	if len(value) < n {
		return nil, ErrInvalid
	}
	return s.cipher.Open(nil, value[:n], value[n:], []byte(context))
}

// totpStep returns the accepted moving factor. The repository must atomically
// enforce step > last_used_step in the same transaction as challenge completion.
func totpStep(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	current := now.Unix() / 30
	for _, step := range []int64{current, current - 1, current + 1} {
		if step <= last || step < 0 {
			continue
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(step))
		h := hmac.New(sha1.New, secret)
		h.Write(b[:])
		sum := h.Sum(nil)
		o := sum[len(sum)-1] & 15
		n := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
		if subtle.ConstantTimeCompare([]byte(fmt.Sprintf("%06d", n%1000000)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
