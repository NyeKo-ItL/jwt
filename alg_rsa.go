package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// minRSABits is the minimum modulus size accepted by every built-in RSA
// constructor (spec §4.6).
const minRSABits = 2048

func rsaHash(alg Algorithm) (crypto.Hash, bool) {
	switch alg {
	case RS256, PS256:
		return crypto.SHA256, true
	case RS384, PS384:
		return crypto.SHA384, true
	case RS512, PS512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func isPSS(alg Algorithm) bool   { return alg == PS256 || alg == PS384 || alg == PS512 }
func isPKCS1(alg Algorithm) bool { return alg == RS256 || alg == RS384 || alg == RS512 }

type rsaPSSSigner struct {
	alg  Algorithm
	key  *rsa.PrivateKey
	kid  string
	hash crypto.Hash
}

// NewRSAPSSSigner returns a PS256/PS384/PS512 (RSA-PSS) Signer. PKCS#1 v1.5
// signing is intentionally not offered as a built-in (spec §0.2).
func NewRSAPSSSigner(alg Algorithm, key *rsa.PrivateKey, kid string) (Signer, error) {
	h, ok := rsaHash(alg)
	if !ok || !isPSS(alg) {
		return nil, fmt.Errorf("%w: %q is not an RSA-PSS algorithm", ErrUnsupportedAlgorithm, alg)
	}
	if key == nil {
		return nil, fmt.Errorf("%w: nil RSA private key", ErrMalformedKey)
	}
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, need >= %d", ErrWeakKey, key.N.BitLen(), minRSABits)
	}
	return &rsaPSSSigner{alg: alg, key: key, kid: kid, hash: h}, nil
}

func (s *rsaPSSSigner) Algorithm() Algorithm { return s.alg }
func (s *rsaPSSSigner) KeyID() string        { return s.kid }

func (s *rsaPSSSigner) Sign(signingInput []byte) ([]byte, error) {
	sum := hashSum(s.hash, signingInput)
	return rsa.SignPSS(rand.Reader, s.key, s.hash, sum, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, // RFC 7518 §3.5
		Hash:       s.hash,
	})
}

type rsaVerifier struct {
	alg  Algorithm
	key  *rsa.PublicKey
	kid  string
	hash crypto.Hash
	pss  bool
}

// NewRSAPSSVerifier returns a PS256/PS384/PS512 Verifier.
func NewRSAPSSVerifier(alg Algorithm, key *rsa.PublicKey, kid string) (Verifier, error) {
	h, ok := rsaHash(alg)
	if !ok || !isPSS(alg) {
		return nil, fmt.Errorf("%w: %q is not an RSA-PSS algorithm", ErrUnsupportedAlgorithm, alg)
	}
	return newRSAVerifier(alg, key, kid, h, true)
}

// NewRSAPKCS1Verifier returns an RS256/RS384/RS512 (PKCS#1 v1.5) Verifier.
// This is verify-only: common external IdPs (Google, Okta, Entra ID) issue
// RS256 ID tokens (spec §0.2).
func NewRSAPKCS1Verifier(alg Algorithm, key *rsa.PublicKey, kid string) (Verifier, error) {
	h, ok := rsaHash(alg)
	if !ok || !isPKCS1(alg) {
		return nil, fmt.Errorf("%w: %q is not an RSA-PKCS1 algorithm", ErrUnsupportedAlgorithm, alg)
	}
	return newRSAVerifier(alg, key, kid, h, false)
}

func newRSAVerifier(alg Algorithm, key *rsa.PublicKey, kid string, h crypto.Hash, pss bool) (Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil RSA public key", ErrMalformedKey)
	}
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, need >= %d", ErrWeakKey, key.N.BitLen(), minRSABits)
	}
	return &rsaVerifier{alg: alg, key: key, kid: kid, hash: h, pss: pss}, nil
}

func (v *rsaVerifier) Algorithm() Algorithm { return v.alg }
func (v *rsaVerifier) KeyID() string        { return v.kid }

func (v *rsaVerifier) Verify(signingInput, signature []byte) error {
	sum := hashSum(v.hash, signingInput)
	var err error
	if v.pss {
		err = rsa.VerifyPSS(v.key, v.hash, sum, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       v.hash,
		})
	} else {
		err = rsa.VerifyPKCS1v15(v.key, v.hash, sum, signature)
	}
	if err != nil {
		return ErrInvalidSignature
	}
	return nil
}
