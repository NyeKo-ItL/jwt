package jwt

import (
	"crypto/ed25519"
	"fmt"
)

type ed25519Signer struct {
	key ed25519.PrivateKey
	kid string
}

// NewEd25519Signer returns an EdDSA (Ed25519, RFC 8037) Signer.
func NewEd25519Signer(key ed25519.PrivateKey, kid string) (Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key must be %d bytes, got %d", ErrMalformedKey, ed25519.PrivateKeySize, len(key))
	}
	return &ed25519Signer{key: append(ed25519.PrivateKey(nil), key...), kid: kid}, nil
}

func (s *ed25519Signer) Algorithm() Algorithm { return EdDSA }
func (s *ed25519Signer) KeyID() string        { return s.kid }

func (s *ed25519Signer) Sign(signingInput []byte) ([]byte, error) {
	return ed25519.Sign(s.key, signingInput), nil
}

type ed25519Verifier struct {
	key ed25519.PublicKey
	kid string
}

// NewEd25519Verifier returns an EdDSA (Ed25519, RFC 8037) Verifier.
func NewEd25519Verifier(key ed25519.PublicKey, kid string) (Verifier, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key must be %d bytes, got %d", ErrMalformedKey, ed25519.PublicKeySize, len(key))
	}
	return &ed25519Verifier{key: append(ed25519.PublicKey(nil), key...), kid: kid}, nil
}

func (v *ed25519Verifier) Algorithm() Algorithm { return EdDSA }
func (v *ed25519Verifier) KeyID() string        { return v.kid }

func (v *ed25519Verifier) Verify(signingInput, signature []byte) error {
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(v.key, signingInput, signature) {
		return ErrInvalidSignature
	}
	return nil
}
