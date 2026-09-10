package jwt

import (
	"crypto"
	"crypto/hmac"
	"fmt"
)

func hmacHash(alg Algorithm) (crypto.Hash, bool) {
	switch alg {
	case HS256:
		return crypto.SHA256, true
	case HS384:
		return crypto.SHA384, true
	case HS512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

type hmacSigner struct {
	alg  Algorithm
	key  []byte
	kid  string
	hash crypto.Hash
}

// NewHMACSigner returns an HS256/HS384/HS512 Signer. The key must be at
// least as long as the hash output (spec §4.6). kid is optional.
func NewHMACSigner(alg Algorithm, key []byte, kid ...string) (Signer, error) {
	h, ok := hmacHash(alg)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an HMAC algorithm", ErrUnsupportedAlgorithm, alg)
	}
	if len(key) < h.Size() {
		return nil, fmt.Errorf("%w: %s needs a key of >= %d bytes, got %d", ErrWeakKey, alg, h.Size(), len(key))
	}
	return &hmacSigner{alg: alg, key: append([]byte(nil), key...), kid: optKID(kid), hash: h}, nil
}

func (s *hmacSigner) Algorithm() Algorithm { return s.alg }
func (s *hmacSigner) KeyID() string        { return s.kid }

func (s *hmacSigner) Sign(signingInput []byte) ([]byte, error) {
	m := hmac.New(s.hash.New, s.key)
	m.Write(signingInput)
	return m.Sum(nil), nil
}

type hmacVerifier struct{ hmacSigner }

// NewHMACVerifier returns an HS256/HS384/HS512 Verifier. The same minimum
// key-size rule as NewHMACSigner applies (spec §4.6). kid is optional.
func NewHMACVerifier(alg Algorithm, key []byte, kid ...string) (Verifier, error) {
	s, err := NewHMACSigner(alg, key, kid...)
	if err != nil {
		return nil, err
	}
	return &hmacVerifier{*s.(*hmacSigner)}, nil
}

func (v *hmacVerifier) Verify(signingInput, signature []byte) error {
	expected, _ := v.Sign(signingInput)
	if !hmac.Equal(expected, signature) {
		return ErrInvalidSignature
	}
	return nil
}
