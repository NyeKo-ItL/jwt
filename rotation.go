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

// NewTokenFamily returns a TokenFamily with a fresh random ID.
//
// It neither returns an error nor panics: since Go 1.24 crypto/rand.Read is
// defined to always succeed, and a catastrophic OS CSPRNG failure aborts the
// program from within the runtime — a condition this package cannot observe
// or recover from.
func NewTokenFamily() TokenFamily {
	buf := make([]byte, familyIDBytes)
	_, _ = rand.Read(buf)
	return TokenFamily{ID: b64.Encode(buf)}
}

// RotationResult is what a storage-backed rotation implementation should
// return; ReuseDetected signals the caller MUST revoke the entire family.
type RotationResult struct {
	Next          OpaqueToken
	ReuseDetected bool
}
