package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// OpaqueToken pairs a random or derived raw credential with its at-rest
// SHA-256 hash. Raw is handed to the client (e.g. in an HttpOnly cookie);
// only Hash is ever persisted.
type OpaqueToken struct {
	Raw  string
	Hash string
}

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
	return OpaqueToken{Raw: raw, Hash: Hash(raw)}, nil
}

// DeriveOpaqueToken deterministically builds a token from a string the
// caller already holds, instead of drawing fresh randomness. Raw is the
// input verbatim; Hash is its SHA-256 hex digest.
func DeriveOpaqueToken(raw string) OpaqueToken {
	return OpaqueToken{Raw: raw, Hash: Hash(raw)}
}

// Hash returns the SHA-256 hex digest of raw.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Equal reports whether raw hashes to storedHash, comparing in constant time
// (crypto/subtle) to avoid leaking the digest through timing.
func Equal(storedHash, raw string) bool {
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(Hash(raw))) == 1
}
