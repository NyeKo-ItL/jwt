package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
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
// "alg":"RSA-OAEP-256"). Keys below 2048 bits are rejected (spec §4.6).
func NewRSAOAEP256Encrypter(pub *rsa.PublicKey, content ContentAlgorithm, kid string) (Encrypter, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: nil RSA public key", ErrMalformedKey)
	}
	if pub.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, need >= %d", ErrWeakKey, pub.N.BitLen(), minRSABits)
	}
	return newEncrypter(content, kid, rsaOAEPWrapper{pub: pub})
}

// NewRSAOAEP256Decrypter unwraps the CEK of a JWE "alg":"RSA-OAEP-256" token.
func NewRSAOAEP256Decrypter(priv *rsa.PrivateKey, kid string) (Decrypter, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: nil RSA private key", ErrMalformedKey)
	}
	if priv.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, need >= %d", ErrWeakKey, priv.N.BitLen(), minRSABits)
	}
	return &decrypter{kid: kid, unwrapper: rsaOAEPUnwrapper{priv: priv}}, nil
}
