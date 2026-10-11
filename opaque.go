package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// OpaqueToken pairs a random or derived raw credential with its at-rest
// SHA-256 hash. Raw is handed to the client (e.g. in an HttpOnly cookie);
// only Hash is ever persisted.
type OpaqueToken struct {
	Raw  string // the credential given to the client; never store it
	Hash string // hex SHA-256 of Raw; the only value to persist
}

// String redacts Raw so logging an OpaqueToken does not disclose the bearer
// credential.
func (t OpaqueToken) String() string {
	return fmt.Sprintf("OpaqueToken{Raw:<redacted>, Hash:%q}", t.Hash)
}

// GoString redacts Raw for %#v formatting as well.
func (t OpaqueToken) GoString() string { return t.String() }

// opaqueTokenBytes is the entropy of a freshly generated opaque token.
const opaqueTokenBytes = 32

// NewOpaqueToken generates a fresh token: 32 bytes of crypto/rand,
// base64url-encoded, paired with its SHA-256 hex digest.
func NewOpaqueToken() (OpaqueToken, error) {
	buf := make([]byte, opaqueTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return OpaqueToken{}, err
	}

	raw := b64.Encode(buf)

	return OpaqueToken{Raw: raw, Hash: HashOpaqueToken(raw)}, nil
}

// OpaqueTokenFromRaw deterministically builds a token from raw instead of
// drawing fresh randomness. It performs only SHA-256 hashing, not password
// stretching: the token is only as strong as raw. Never use a password,
// short code, predictable identifier, or other low-entropy input.
func OpaqueTokenFromRaw(raw string) OpaqueToken {
	return OpaqueToken{Raw: raw, Hash: HashOpaqueToken(raw)}
}

// HashOpaqueToken returns the SHA-256 hex digest persisted for a raw opaque
// token.
func HashOpaqueToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// VerifyOpaqueTokenHash reports whether raw matches storedHash, comparing in
// constant time (crypto/subtle) to avoid leaking the digest through timing.
func VerifyOpaqueTokenHash(storedHash, raw string) bool {
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(HashOpaqueToken(raw))) == 1
}

// DeriveOpaqueToken deterministically builds a token from caller-provided raw
// input.
//
// Deprecated: use OpaqueTokenFromRaw. Derived tokens are only as strong as the
// input and must not be created from low-entropy secrets.
func DeriveOpaqueToken(raw string) OpaqueToken { return OpaqueTokenFromRaw(raw) }

// Hash returns the SHA-256 hex digest of raw.
//
// Deprecated: use HashOpaqueToken.
func Hash(raw string) string { return HashOpaqueToken(raw) }

// Equal reports whether raw matches storedHash.
//
// Deprecated: use VerifyOpaqueTokenHash.
func Equal(storedHash, raw string) bool { return VerifyOpaqueTokenHash(storedHash, raw) }
