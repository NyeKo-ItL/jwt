package jwt

import (
	"errors"

	internalalg "github.com/NyeKo-ItL/jwt/internal/alg"
)

// Sentinel errors. All are comparable with errors.Is (spec §6.3); returned
// errors usually wrap one of them with detail that is safe to log but not
// meant for clients (see WriteChallenge).
var (
	// ErrInvalidSignature reports a JWS signature or MAC that does not verify
	// (RFC 7515 §5.2 step 8).
	ErrInvalidSignature = internalalg.ErrInvalidSignature
	// ErrExpired reports that the current time is not before "exp" (minus
	// leeway) — RFC 7519 §4.1.4.
	ErrExpired = errors.New("jwt: token expired")
	// ErrNotYetValid reports that the current time is before "nbf" (plus
	// leeway) — RFC 7519 §4.1.5.
	ErrNotYetValid = errors.New("jwt: token not yet valid")
	// ErrIssuerMismatch reports an "iss" different from WithIssuer
	// (RFC 7519 §4.1.1, RFC 8725 §3.8).
	ErrIssuerMismatch = errors.New("jwt: issuer mismatch")
	// ErrAudienceMismatch reports an "aud" that does not identify this
	// recipient, or a missing "aud" when WithAudience is set (RFC 7519 §4.1.3,
	// RFC 8725 §3.9).
	ErrAudienceMismatch = errors.New("jwt: audience mismatch")
	// ErrAlgorithmNotAllowed reports a header "alg" (or JWE "enc") outside the
	// caller's allowlist, "none", or a key family that cannot serve the
	// algorithm (RFC 8725 §3.1).
	ErrAlgorithmNotAllowed = errors.New("jwt: algorithm not in allowlist")
	// ErrNoAllowedAlgorithms reports a missing mandatory allowlist — a
	// configuration error, not a token error (RFC 8725 §3.1).
	ErrNoAllowedAlgorithms = errors.New("jwt: WithAllowedAlgorithms is required")
	// ErrMissingClaim reports a claim required by WithRequiredClaims or a
	// profile validator (e.g. RFC 9068 §2.2) that is absent.
	ErrMissingClaim = errors.New("jwt: required claim missing")
	// ErrMalformedToken reports input that is not a well-formed compact
	// JWS/JWT: wrong segment count, non-canonical base64url, invalid or
	// duplicate-member JSON, a non-object header or claim set, or oversize.
	ErrMalformedToken = errors.New("jwt: malformed token")
	// ErrTypeMismatch reports a "typ" header different from WithRequiredType
	// (RFC 8725 §3.11).
	ErrTypeMismatch = errors.New("jwt: unexpected \"typ\" header")

	// ErrWeakKey reports key material below the enforced minimum: HMAC keys
	// shorter than the hash output (RFC 7518 §3.2), RSA below 2048 bits
	// (RFC 7518 §3.3, §4.2).
	ErrWeakKey = internalalg.ErrWeakKey
	// ErrUnsupportedAlgorithm reports an algorithm with no built-in
	// implementation, or a nil Signer/Encrypter/Decrypter.
	ErrUnsupportedAlgorithm = internalalg.ErrUnsupportedAlgorithm
	// ErrKeyNotFound reports that the KeyProvider has no key for the token's
	// "kid" (or several candidates for an empty "kid").
	ErrKeyNotFound = errors.New("jwt: no key for kid")
	// ErrKeyTypeMismatch reports key material of the wrong type or curve for
	// the requested algorithm (spec §4.10).
	ErrKeyTypeMismatch = internalalg.ErrKeyTypeMismatch
	// ErrMalformedKey reports unusable key material: invalid JWK members,
	// non-canonical encodings (RFC 7518 §6), points off the curve, or
	// unparsable DER/SSH input.
	ErrMalformedKey = internalalg.ErrMalformedKey
	// ErrOctNotServable is returned when marshaling a symmetric "oct" key,
	// which must never be published in a JWKS document (spec §5.3).
	ErrOctNotServable = errors.New("jwt: oct keys must not be serialized into a JWKS document")

	// ErrKeyUsage reports a key whose own "use", "key_ops" or "alg" member
	// (RFC 7517 §4.2–4.4) does not permit the requested operation.
	ErrKeyUsage = errors.New("jwt: key is not permitted for this operation")

	// ErrUnsupportedCritical reports a "crit" header (RFC 7515 §4.1.11,
	// RFC 7516 §4.1.13) listing extensions this library does not implement,
	// or a malformed "crit" value. Such a token is always invalid.
	ErrUnsupportedCritical = errors.New("jwt: unsupported critical header parameter")
)
