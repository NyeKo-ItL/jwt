package jwt

import (
	"errors"

	internalalg "github.com/NyeKo-ItL/jwt/internal/alg"
)

// Sentinel errors. All are comparable with errors.Is (spec §6.3).
var (
	ErrInvalidSignature    = internalalg.ErrInvalidSignature
	ErrExpired             = errors.New("jwt: token expired")
	ErrNotYetValid         = errors.New("jwt: token not yet valid")
	ErrIssuerMismatch      = errors.New("jwt: issuer mismatch")
	ErrAudienceMismatch    = errors.New("jwt: audience mismatch")
	ErrAlgorithmNotAllowed = errors.New("jwt: algorithm not in allowlist")
	ErrNoAllowedAlgorithms = errors.New("jwt: WithAllowedAlgorithms is required")
	ErrMissingClaim        = errors.New("jwt: required claim missing")
	ErrMalformedToken      = errors.New("jwt: malformed token")
	ErrTypeMismatch        = errors.New("jwt: unexpected \"typ\" header")

	// Sentinels beyond the §5.1 list, needed by the constructors and the
	// key-resolution path.
	ErrWeakKey              = internalalg.ErrWeakKey
	ErrUnsupportedAlgorithm = internalalg.ErrUnsupportedAlgorithm
	ErrKeyNotFound          = errors.New("jwt: no key for kid")
	ErrKeyTypeMismatch      = internalalg.ErrKeyTypeMismatch
	ErrMalformedKey         = internalalg.ErrMalformedKey
	ErrOctNotServable       = errors.New("jwt: oct keys must not be serialized into a JWKS document")

	// ErrKeyUsage reports a key whose own "use", "key_ops" or "alg" member
	// (RFC 7517 §4.2–4.4) does not permit the requested operation.
	ErrKeyUsage = errors.New("jwt: key is not permitted for this operation")

	// ErrUnsupportedCritical reports a "crit" header (RFC 7515 §4.1.11,
	// RFC 7516 §4.1.13) listing extensions this library does not implement,
	// or a malformed "crit" value. Such a token is always invalid.
	ErrUnsupportedCritical = errors.New("jwt: unsupported critical header parameter")
)
