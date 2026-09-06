package jwt

import (
	"crypto"
	_ "crypto/sha256" // register SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // register SHA-384 / SHA-512 for crypto.Hash.New
)

// Algorithm identifies a JWA/EdDSA signing algorithm. It is an open string
// type, not a closed enum: a caller implementing a custom Signer/Verifier
// can define their own Algorithm value and it works exactly like a built-in
// one everywhere an Algorithm is accepted (spec §0.2, §5.1).
type Algorithm string

// Registered algorithm identifiers (spec §5.1). "none" (RFC 7518 §3.6)
// deliberately has no constant and is never representable in either
// direction (spec §0.2, §4.2).
const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256" // built-in verify-only (spec §0.2)
	RS384 Algorithm = "RS384" // built-in verify-only
	RS512 Algorithm = "RS512" // built-in verify-only
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	EdDSA Algorithm = "EdDSA"
)

// Signer produces a JWS signature over the ASCII signing input
// "<base64url header>.<base64url payload>" (RFC 7515 §5.1). It is a plain
// interface: a caller may implement it for an algorithm the built-in
// constructors do not cover (e.g. PKCS#1 v1.5 RSA, or an HSM/KMS-backed
// key). Sign has no type-switch over a closed set of known signers.
type Signer interface {
	Algorithm() Algorithm
	KeyID() string // RFC 7515 §4.1.4 "kid"; empty if the key has none
	Sign(signingInput []byte) (signature []byte, err error)
}

// Verifier checks a JWS signature. The library ships constructors for the
// full applicable registry, including verify-only algorithms, because it
// must validate tokens issued by third parties this library would never
// itself sign with. Like Signer, it is a plain interface open to caller
// extension.
type Verifier interface {
	Algorithm() Algorithm
	KeyID() string
	Verify(signingInput, signature []byte) error
}

// algFamily groups algorithms that share a key type, used for the
// anti-confusion check at key-resolution time (spec §4.10).
type algFamily int

const (
	familyUnknown algFamily = iota
	familyHMAC
	familyRSAPSS
	familyRSAPKCS1
	familyECDSA
	familyEdDSA
)

func family(alg Algorithm) algFamily {
	switch alg {
	case HS256, HS384, HS512:
		return familyHMAC
	case PS256, PS384, PS512:
		return familyRSAPSS
	case RS256, RS384, RS512:
		return familyRSAPKCS1
	case ES256, ES384, ES512:
		return familyECDSA
	case EdDSA:
		return familyEdDSA
	default:
		return familyUnknown
	}
}

// hashSum returns h(in). h must be a registered crypto.Hash.
func hashSum(h crypto.Hash, in []byte) []byte {
	hh := h.New()
	hh.Write(in)
	return hh.Sum(nil)
}
