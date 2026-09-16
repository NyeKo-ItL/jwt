package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	internalalg "github.com/NyeKo-ItL/jwt/internal/alg"
)

// Algorithm identifies a JWS signing algorithm (RFC 7518 §3, RFC 9864 §2.2). It is an open string
// type, not a closed enum: callers may define custom algorithm values.
type Algorithm = internalalg.Algorithm

const (
	HS256 Algorithm = internalalg.HS256
	HS384 Algorithm = internalalg.HS384
	HS512 Algorithm = internalalg.HS512
	RS256 Algorithm = internalalg.RS256
	RS384 Algorithm = internalalg.RS384
	RS512 Algorithm = internalalg.RS512
	PS256 Algorithm = internalalg.PS256
	PS384 Algorithm = internalalg.PS384
	PS512 Algorithm = internalalg.PS512
	ES256 Algorithm = internalalg.ES256
	ES384 Algorithm = internalalg.ES384
	ES512 Algorithm = internalalg.ES512
	// Ed25519 is EdDSA using the Ed25519 parameter set (RFC 9864 §2.2,
	// RFC 8032 §5.1) — the fully-specified identifier the built-in Ed25519
	// signer emits.
	Ed25519 Algorithm = internalalg.Ed25519

	// EdDSA is the polymorphic identifier of RFC 8037 §3.1.
	//
	// Deprecated: RFC 9864 §4.1.2 deprecates "EdDSA" in favor of Ed25519.
	// It is still verified — over Ed25519 keys only — when explicitly listed
	// in WithAllowedAlgorithms, for tokens from issuers that have not
	// migrated; nothing in this library emits it.
	EdDSA Algorithm = internalalg.EdDSA
)

// Signer produces a JWS signature over the ASCII signing input.
type Signer = internalalg.Signer

// Verifier checks a JWS signature.
type Verifier = internalalg.Verifier

// NewHMACSigner returns an HS256/HS384/HS512 Signer.
func NewHMACSigner(alg Algorithm, key []byte, kid ...string) (Signer, error) {
	return internalalg.NewHMACSigner(alg, key, kid...)
}

// NewHMACVerifier returns an HS256/HS384/HS512 Verifier.
func NewHMACVerifier(alg Algorithm, key []byte, kid ...string) (Verifier, error) {
	return internalalg.NewHMACVerifier(alg, key, kid...)
}

// NewECDSASigner returns an ES256/ES384/ES512 Signer.
func NewECDSASigner(alg Algorithm, key *ecdsa.PrivateKey, kid ...string) (Signer, error) {
	return internalalg.NewECDSASigner(alg, key, kid...)
}

// NewECDSAVerifier returns an ES256/ES384/ES512 Verifier.
func NewECDSAVerifier(alg Algorithm, key *ecdsa.PublicKey, kid ...string) (Verifier, error) {
	return internalalg.NewECDSAVerifier(alg, key, kid...)
}

// NewRSAPSSSigner returns a PS256/PS384/PS512 Signer.
func NewRSAPSSSigner(alg Algorithm, key *rsa.PrivateKey, kid ...string) (Signer, error) {
	return internalalg.NewRSAPSSSigner(alg, key, kid...)
}

// NewRSAPSSVerifier returns a PS256/PS384/PS512 Verifier.
func NewRSAPSSVerifier(alg Algorithm, key *rsa.PublicKey, kid ...string) (Verifier, error) {
	return internalalg.NewRSAPSSVerifier(alg, key, kid...)
}

// NewRSAPKCS1Verifier returns an RS256/RS384/RS512 Verifier.
func NewRSAPKCS1Verifier(alg Algorithm, key *rsa.PublicKey, kid ...string) (Verifier, error) {
	return internalalg.NewRSAPKCS1Verifier(alg, key, kid...)
}

// NewEd25519Signer returns a Signer for the RFC 9864 "Ed25519" algorithm.
func NewEd25519Signer(key ed25519.PrivateKey, kid ...string) (Signer, error) {
	return internalalg.NewEd25519Signer(key, kid...)
}

// NewEd25519Verifier returns a Verifier for the RFC 9864 "Ed25519"
// algorithm. Parse also verifies deprecated "EdDSA" tokens with an Ed25519
// key when EdDSA is allowlisted.
func NewEd25519Verifier(key ed25519.PublicKey, kid ...string) (Verifier, error) {
	return internalalg.NewEd25519Verifier(key, kid...)
}
