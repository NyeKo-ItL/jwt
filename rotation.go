package jwt

import (
	"crypto/rand"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// TokenFamily identifies a lineage of rotated tokens sharing one logical
// session, so that presenting an already-rotated-away token can be detected
// as reuse and the whole family revoked — a common refresh-token-rotation
// pattern. The library defines the shape; storage is the caller's (see
// RevocationStore, §5.6).
type TokenFamily struct{ ID string }

// familyIDBytes is the entropy of a generated family identifier.
const familyIDBytes = 16

// NewTokenFamily returns a TokenFamily with a fresh random ID. It panics
// only if the system CSPRNG fails, which Go treats as unrecoverable.
func NewTokenFamily() TokenFamily {
	buf := make([]byte, familyIDBytes)
	if _, err := rand.Read(buf); err != nil {
		panic("jwt: crypto/rand failed: " + err.Error())
	}
	return TokenFamily{ID: b64.Encode(buf)}
}

// RotationResult is what a storage-backed rotation implementation should
// return; ReuseDetected signals the caller MUST revoke the entire family.
type RotationResult struct {
	Next          OpaqueToken
	ReuseDetected bool
}
