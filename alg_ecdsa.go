package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

// ecdsaParams maps an ES* algorithm to its curve, digest, and the
// fixed length (in bytes) of each of r and s in the JWS signature
// (RFC 7518 §3.4 — fixed-length concatenation, not ASN.1 DER).
func ecdsaParams(alg Algorithm) (elliptic.Curve, crypto.Hash, int, bool) {
	switch alg {
	case ES256:
		return elliptic.P256(), crypto.SHA256, 32, true
	case ES384:
		return elliptic.P384(), crypto.SHA384, 48, true
	case ES512:
		return elliptic.P521(), crypto.SHA512, 66, true
	default:
		return nil, 0, 0, false
	}
}

type ecdsaSigner struct {
	alg  Algorithm
	key  *ecdsa.PrivateKey
	kid  string
	hash crypto.Hash
	size int
}

// NewECDSASigner returns an ES256/ES384/ES512 Signer. The key's curve must
// match the algorithm.
func NewECDSASigner(alg Algorithm, key *ecdsa.PrivateKey, kid string) (Signer, error) {
	curve, h, size, ok := ecdsaParams(alg)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an ECDSA algorithm", ErrUnsupportedAlgorithm, alg)
	}
	if key == nil {
		return nil, fmt.Errorf("%w: nil ECDSA private key", ErrMalformedKey)
	}
	if key.Curve != curve {
		return nil, fmt.Errorf("%w: %s requires curve %s", ErrKeyTypeMismatch, alg, curve.Params().Name)
	}
	return &ecdsaSigner{alg: alg, key: key, kid: kid, hash: h, size: size}, nil
}

func (s *ecdsaSigner) Algorithm() Algorithm { return s.alg }
func (s *ecdsaSigner) KeyID() string        { return s.kid }

func (s *ecdsaSigner) Sign(signingInput []byte) ([]byte, error) {
	sum := hashSum(s.hash, signingInput)
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, sum)
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

// NewECDSAVerifier returns an ES256/ES384/ES512 Verifier.
func NewECDSAVerifier(alg Algorithm, key *ecdsa.PublicKey, kid string) (Verifier, error) {
	curve, h, size, ok := ecdsaParams(alg)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an ECDSA algorithm", ErrUnsupportedAlgorithm, alg)
	}
	if key == nil {
		return nil, fmt.Errorf("%w: nil ECDSA public key", ErrMalformedKey)
	}
	if key.Curve != curve {
		return nil, fmt.Errorf("%w: %s requires curve %s", ErrKeyTypeMismatch, alg, curve.Params().Name)
	}
	return &ecdsaVerifier{alg: alg, key: key, kid: kid, hash: h, size: size}, nil
}

func (v *ecdsaVerifier) Algorithm() Algorithm { return v.alg }
func (v *ecdsaVerifier) KeyID() string        { return v.kid }

func (v *ecdsaVerifier) Verify(signingInput, signature []byte) error {
	if len(signature) != 2*v.size {
		return ErrInvalidSignature
	}
	r := new(big.Int).SetBytes(signature[:v.size])
	s := new(big.Int).SetBytes(signature[v.size:])
	sum := hashSum(v.hash, signingInput)
	if !ecdsa.Verify(v.key, sum, r, s) {
		return ErrInvalidSignature
	}
	return nil
}
