// Package alg contains the built-in JWS algorithms. It is internal so the
// concrete signing and verification implementations are not part of jwt's
// public API.
package alg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"

	_ "crypto/sha256" // registers SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for crypto.Hash.New

	internalerr "github.com/NyeKo-ItL/jwt/internal/errors"
)

// Algorithm identifies a JWA signing algorithm.
type Algorithm string

// JWS algorithm identifiers (RFC 7518 §3.1, RFC 9864 §2.2); the public jwt
// package documents each one.
const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	// Ed25519 is the fully-specified EdDSA-over-Ed25519 identifier
	// (RFC 9864 §2.2).
	Ed25519 Algorithm = "Ed25519"
	// EdDSA is the polymorphic identifier from RFC 8037, deprecated by
	// RFC 9864 §4.1.2; only Ed25519 keys are supported for it.
	EdDSA Algorithm = "EdDSA"
)

// Signer produces a JWS signature.
type Signer interface {
	Algorithm() Algorithm
	KeyID() string
	Sign([]byte) ([]byte, error)
}

// Verifier checks a JWS signature.
type Verifier interface {
	Algorithm() Algorithm
	KeyID() string
	Verify([]byte, []byte) error
}

// Sentinel errors, re-exported by the jwt package.
var (
	ErrInvalidSignature     = internalerr.ErrInvalidSignature
	ErrWeakKey              = internalerr.ErrWeakKey
	ErrUnsupportedAlgorithm = internalerr.ErrUnsupportedAlgorithm
	ErrKeyTypeMismatch      = internalerr.ErrKeyTypeMismatch
	ErrMalformedKey         = internalerr.ErrMalformedKey
)

func optKID(kid []string) string {
	if len(kid) > 0 {
		return kid[0]
	}

	return ""
}

// Family identifies the key family used by a JWS algorithm.
type Family uint8

// Algorithm families; a key can only serve algorithms of its own family.
const (
	FamilyUnknown Family = iota
	FamilyHMAC
	FamilyRSAPSS
	FamilyRSAPKCS1
	FamilyECDSA
	FamilyEdDSA
)

// FamilyOf returns the key family an algorithm name belongs to.
func FamilyOf(name string) Family {
	switch name {
	case "HS256", "HS384", "HS512":
		return FamilyHMAC
	case "PS256", "PS384", "PS512":
		return FamilyRSAPSS
	case "RS256", "RS384", "RS512":
		return FamilyRSAPKCS1
	case "ES256", "ES384", "ES512":
		return FamilyECDSA
	case "Ed25519", "EdDSA":
		return FamilyEdDSA
	default:
		return FamilyUnknown
	}
}

// Hash returns the hash used by an HS*, RS* or PS* algorithm.
func Hash(name string) (crypto.Hash, bool) {
	switch name {
	case "HS256", "RS256", "PS256":
		return crypto.SHA256, true
	case "HS384", "RS384", "PS384":
		return crypto.SHA384, true
	case "HS512", "RS512", "PS512":
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

// IsPSS reports whether name is a PS* (RSASSA-PSS) algorithm.
func IsPSS(name string) bool { return name == "PS256" || name == "PS384" || name == "PS512" }

// IsPKCS1 reports whether name is an RS* (RSASSA-PKCS1-v1_5) algorithm.
func IsPKCS1(name string) bool { return name == "RS256" || name == "RS384" || name == "RS512" }

// ECDSAParams returns the curve, hash and per-integer signature size (in
// bytes) of an ES* algorithm (RFC 7518 §3.4).
func ECDSAParams(name string) (elliptic.Curve, crypto.Hash, int, bool) {
	switch name {
	case "ES256":
		return elliptic.P256(), crypto.SHA256, 32, true
	case "ES384":
		return elliptic.P384(), crypto.SHA384, 48, true
	case "ES512":
		return elliptic.P521(), crypto.SHA512, 66, true
	default:
		return nil, 0, 0, false
	}
}

// HashSum returns h(in).
func HashSum(h crypto.Hash, in []byte) []byte {
	hh := h.New()
	hh.Write(in)

	return hh.Sum(nil)
}

type hmacSigner struct {
	alg  Algorithm
	key  []byte
	kid  string
	hash crypto.Hash
}

// NewHMACSigner returns an HS* Signer. Keys shorter than the hash output are
// rejected with ErrWeakKey (RFC 7518 §3.2).
func NewHMACSigner(a Algorithm, key []byte, kid ...string) (Signer, error) {
	h, ok := Hash(string(a))
	if !ok || FamilyOf(string(a)) != FamilyHMAC {
		return nil, fmt.Errorf("%w: %q is not an HMAC algorithm", ErrUnsupportedAlgorithm, a)
	}

	if len(key) < h.Size() {
		return nil, fmt.Errorf("%w: %s needs a key of >= %d bytes, got %d", ErrWeakKey, a, h.Size(), len(key))
	}

	return &hmacSigner{alg: a, key: append([]byte(nil), key...), kid: optKID(kid), hash: h}, nil
}
func (s *hmacSigner) Algorithm() Algorithm { return s.alg }
func (s *hmacSigner) KeyID() string        { return s.kid }
func (s *hmacSigner) Sign(in []byte) ([]byte, error) {
	m := hmac.New(s.hash.New, s.key)
	m.Write(in)

	return m.Sum(nil), nil
}

type hmacVerifier struct{ hmacSigner }

// NewHMACVerifier returns an HS* Verifier that compares MACs in constant
// time.
func NewHMACVerifier(a Algorithm, key []byte, kid ...string) (Verifier, error) {
	s, err := NewHMACSigner(a, key, kid...)
	if err != nil {
		return nil, err
	}

	return &hmacVerifier{*s.(*hmacSigner)}, nil
}
func (v *hmacVerifier) Verify(in, sig []byte) error {
	expected, _ := v.Sign(in)
	if !hmac.Equal(expected, sig) {
		return ErrInvalidSignature
	}

	return nil
}

type ecdsaSigner struct {
	alg  Algorithm
	key  *ecdsa.PrivateKey
	kid  string
	hash crypto.Hash
	size int
}

// NewECDSASigner returns an ES* Signer producing the fixed-length R||S
// encoding (RFC 7518 §3.4), not ASN.1 DER.
func NewECDSASigner(a Algorithm, key *ecdsa.PrivateKey, kid ...string) (Signer, error) {
	curve, h, size, ok := ECDSAParams(string(a))
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an ECDSA algorithm", ErrUnsupportedAlgorithm, a)
	}

	if key == nil {
		return nil, fmt.Errorf("%w: nil ECDSA private key", ErrMalformedKey)
	}

	if key.Curve != curve {
		return nil, fmt.Errorf("%w: %s requires curve %s", ErrKeyTypeMismatch, a, curve.Params().Name)
	}

	return &ecdsaSigner{a, key, optKID(kid), h, size}, nil
}
func (s *ecdsaSigner) Algorithm() Algorithm { return s.alg }
func (s *ecdsaSigner) KeyID() string        { return s.kid }
func (s *ecdsaSigner) Sign(in []byte) ([]byte, error) {
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, HashSum(s.hash, in))
	if err != nil {
		return nil, err
	}

	out := make([]byte, 2*s.size)
	r.FillBytes(out[:s.size])
	ss.FillBytes(out[s.size:])

	return out, nil
}

type ecdsaVerifier struct {
	alg  Algorithm
	key  *ecdsa.PublicKey
	kid  string
	hash crypto.Hash
	size int
}

// NewECDSAVerifier returns an ES* Verifier; the key curve must match the
// algorithm.
func NewECDSAVerifier(a Algorithm, key *ecdsa.PublicKey, kid ...string) (Verifier, error) {
	curve, h, size, ok := ECDSAParams(string(a))
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an ECDSA algorithm", ErrUnsupportedAlgorithm, a)
	}

	if key == nil {
		return nil, fmt.Errorf("%w: nil ECDSA public key", ErrMalformedKey)
	}

	if key.Curve != curve {
		return nil, fmt.Errorf("%w: %s requires curve %s", ErrKeyTypeMismatch, a, curve.Params().Name)
	}

	return &ecdsaVerifier{a, key, optKID(kid), h, size}, nil
}
func (v *ecdsaVerifier) Algorithm() Algorithm { return v.alg }
func (v *ecdsaVerifier) KeyID() string        { return v.kid }
func (v *ecdsaVerifier) Verify(in, sig []byte) error {
	if len(sig) != 2*v.size {
		return ErrInvalidSignature
	}

	r := new(big.Int).SetBytes(sig[:v.size])

	s := new(big.Int).SetBytes(sig[v.size:])
	if !ecdsa.Verify(v.key, HashSum(v.hash, in), r, s) {
		return ErrInvalidSignature
	}

	return nil
}

type rsaPSSSigner struct {
	alg  Algorithm
	key  *rsa.PrivateKey
	kid  string
	hash crypto.Hash
}
type rsaVerifier struct {
	alg  Algorithm
	key  *rsa.PublicKey
	kid  string
	hash crypto.Hash
	pss  bool
}

const minRSABits = 2048

// NewRSAPSSSigner returns a PS* Signer (salt length = hash size, RFC 7518
// §3.5). Keys below 2048 bits are rejected.
func NewRSAPSSSigner(a Algorithm, key *rsa.PrivateKey, kid ...string) (Signer, error) {
	h, ok := Hash(string(a))
	if !ok || !IsPSS(string(a)) {
		return nil, fmt.Errorf("%w: %q is not an RSA-PSS algorithm", ErrUnsupportedAlgorithm, a)
	}

	if key == nil {
		return nil, fmt.Errorf("%w: nil RSA private key", ErrMalformedKey)
	}

	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, need >= %d", ErrWeakKey, key.N.BitLen(), minRSABits)
	}

	return &rsaPSSSigner{a, key, optKID(kid), h}, nil
}
func (s *rsaPSSSigner) Algorithm() Algorithm { return s.alg }
func (s *rsaPSSSigner) KeyID() string        { return s.kid }
func (s *rsaPSSSigner) Sign(in []byte) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, s.key, s.hash, HashSum(s.hash, in), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: s.hash})
}
func newRSAVerifier(a Algorithm, key *rsa.PublicKey, kid string, h crypto.Hash, pss bool) (Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil RSA public key", ErrMalformedKey)
	}

	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, need >= %d", ErrWeakKey, key.N.BitLen(), minRSABits)
	}

	return &rsaVerifier{a, key, kid, h, pss}, nil
}

// NewRSAPSSVerifier returns a PS* Verifier. Keys below 2048 bits are
// rejected.
func NewRSAPSSVerifier(a Algorithm, key *rsa.PublicKey, kid ...string) (Verifier, error) {
	h, ok := Hash(string(a))
	if !ok || !IsPSS(string(a)) {
		return nil, fmt.Errorf("%w: %q is not an RSA-PSS algorithm", ErrUnsupportedAlgorithm, a)
	}

	return newRSAVerifier(a, key, optKID(kid), h, true)
}

// NewRSAPKCS1Verifier returns an RS* Verifier (verification only). Keys
// below 2048 bits are rejected.
func NewRSAPKCS1Verifier(a Algorithm, key *rsa.PublicKey, kid ...string) (Verifier, error) {
	h, ok := Hash(string(a))
	if !ok || !IsPKCS1(string(a)) {
		return nil, fmt.Errorf("%w: %q is not an RSA-PKCS1 algorithm", ErrUnsupportedAlgorithm, a)
	}

	return newRSAVerifier(a, key, optKID(kid), h, false)
}
func (v *rsaVerifier) Algorithm() Algorithm { return v.alg }
func (v *rsaVerifier) KeyID() string        { return v.kid }
func (v *rsaVerifier) Verify(in, sig []byte) error {
	var err error

	sum := HashSum(v.hash, in)
	if v.pss {
		err = rsa.VerifyPSS(v.key, v.hash, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: v.hash})
	} else {
		err = rsa.VerifyPKCS1v15(v.key, v.hash, sum, sig)
	}

	if err != nil {
		return ErrInvalidSignature
	}

	return nil
}

type ed25519Signer struct {
	key ed25519.PrivateKey
	kid string
}

// NewEd25519Signer returns a Signer for "Ed25519" (RFC 9864 §2.2).
func NewEd25519Signer(key ed25519.PrivateKey, kid ...string) (Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key must be %d bytes, got %d", ErrMalformedKey, ed25519.PrivateKeySize, len(key))
	}

	return &ed25519Signer{append(ed25519.PrivateKey(nil), key...), optKID(kid)}, nil
}
func (s *ed25519Signer) Algorithm() Algorithm           { return Ed25519 }
func (s *ed25519Signer) KeyID() string                  { return s.kid }
func (s *ed25519Signer) Sign(in []byte) ([]byte, error) { return ed25519.Sign(s.key, in), nil }

type ed25519Verifier struct {
	alg Algorithm
	key ed25519.PublicKey
	kid string
}

// NewEd25519Verifier returns a Verifier for the RFC 9864 "Ed25519" algorithm.
func NewEd25519Verifier(key ed25519.PublicKey, kid ...string) (Verifier, error) {
	return NewEd25519VerifierFor(Ed25519, key, kid...)
}

// NewEd25519VerifierFor returns an Ed25519 Verifier reporting alg, which must
// be Ed25519 or the deprecated polymorphic EdDSA (RFC 9864 §4.1.2); both
// denote the same computation over an Ed25519 key.
func NewEd25519VerifierFor(a Algorithm, key ed25519.PublicKey, kid ...string) (Verifier, error) {
	if a != Ed25519 && a != EdDSA {
		return nil, fmt.Errorf("%w: %q is not an Ed25519 algorithm", ErrUnsupportedAlgorithm, a)
	}

	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key must be %d bytes, got %d", ErrMalformedKey, ed25519.PublicKeySize, len(key))
	}

	return &ed25519Verifier{a, append(ed25519.PublicKey(nil), key...), optKID(kid)}, nil
}
func (v *ed25519Verifier) Algorithm() Algorithm { return v.alg }
func (v *ed25519Verifier) KeyID() string        { return v.kid }
func (v *ed25519Verifier) Verify(in, sig []byte) error {
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(v.key, in, sig) {
		return ErrInvalidSignature
	}

	return nil
}
