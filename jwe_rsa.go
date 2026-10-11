package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/NyeKo-ItL/jwt/internal/option"
)

const (
	minRSABits    = 2048
	maxJWERSABits = 8192
)

type rsaOAEPWrapper struct{ pub *rsa.PublicKey }

func (rsaOAEPWrapper) keyAlg() KeyAlgorithm { return RSAOAEP256 }

func (w rsaOAEPWrapper) wrap(_ *jweHeader, cekLen int) (cek, encryptedKey []byte, err error) {
	cek = make([]byte, cekLen)
	if _, err = rand.Read(cek); err != nil {
		return nil, nil, err
	}

	encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, w.pub, cek, nil)

	return cek, encryptedKey, err
}

type rsaOAEPUnwrapper struct{ priv *rsa.PrivateKey }

func (rsaOAEPUnwrapper) supports(alg KeyAlgorithm) bool { return alg == RSAOAEP256 }

func (u rsaOAEPUnwrapper) unwrap(_ *jweHeader, encryptedKey []byte, cekLen int) ([]byte, error) {
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, u.priv, encryptedKey, nil)
	if err != nil || len(cek) != cekLen {
		return nil, ErrDecryptionFailed
	}

	return cek, nil
}

// NewRSAOAEP256Encrypter wraps a fresh CEK with RSA-OAEP using SHA-256 (JWE
// "alg":"RSA-OAEP-256"). Keys must be between 2048 and 8192 bits. This
// asymmetric JWE encryption authenticates the ciphertext to the recipient but
// does not authenticate its sender; sign before encrypting, preferably with
// EncryptNestedJWT, when issuer authentication is required.
func NewRSAOAEP256Encrypter(pub *rsa.PublicKey, content ContentAlgorithm, kid ...string) (Encrypter, error) {
	if err := validateJWERSAPublicKey(pub); err != nil {
		return nil, err
	}

	return newEncrypter(content, option.FirstString(kid), rsaOAEPWrapper{pub: pub})
}

// NewRSAOAEP256Decrypter unwraps the CEK of a JWE "alg":"RSA-OAEP-256" token.
// Keys must be complete, internally consistent, and at most 8192 bits.
func NewRSAOAEP256Decrypter(priv *rsa.PrivateKey, kid ...string) (Decrypter, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: nil RSA private key", ErrMalformedKey)
	}

	if err := validateJWERSAPublicKey(&priv.PublicKey); err != nil {
		return nil, err
	}

	if priv.D == nil || priv.D.Sign() <= 0 || len(priv.Primes) < 2 {
		return nil, fmt.Errorf("%w: incomplete RSA private key", ErrMalformedKey)
	}

	for _, prime := range priv.Primes {
		if prime == nil || prime.Sign() <= 0 {
			return nil, fmt.Errorf("%w: incomplete RSA private key", ErrMalformedKey)
		}
	}

	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("%w: invalid RSA private key: %w", ErrMalformedKey, err)
	}

	return &decrypter{kid: option.FirstString(kid), unwrapper: rsaOAEPUnwrapper{priv: priv}}, nil
}

func validateJWERSAPublicKey(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 {
		return fmt.Errorf("%w: incomplete RSA public key", ErrMalformedKey)
	}

	bits := pub.N.BitLen()
	if bits < minRSABits {
		return fmt.Errorf("%w: RSA key is %d bits, need >= %d", ErrWeakKey, bits, minRSABits)
	}

	if bits > maxJWERSABits {
		return fmt.Errorf("%w: RSA key is %d bits, maximum is %d", ErrMalformedKey, bits, maxJWERSABits)
	}

	if pub.N.Bit(0) == 0 || pub.E < 3 || pub.E&1 == 0 || pub.E > 1<<31-1 {
		return fmt.Errorf("%w: invalid RSA modulus or public exponent", ErrMalformedKey)
	}

	return nil
}
