package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

func TestECDSARoundTrip(t *testing.T) {
	tk := newTestKeys(t)
	cases := []struct {
		alg  Algorithm
		key  *ecdsa.PrivateKey
		size int
	}{
		{ES256, tk.p256, 64},
		{ES384, tk.p384, 96},
		{ES512, tk.p521, 132},
	}
	for _, c := range cases {
		s, err := NewECDSASigner(c.alg, c.key, "e1")
		if err != nil {
			t.Fatalf("%s: signer: %v", c.alg, err)
		}
		sig, err := s.Sign([]byte("a.b"))
		if err != nil {
			t.Fatalf("%s: sign: %v", c.alg, err)
		}
		if len(sig) != c.size {
			t.Fatalf("%s: signature length = %d, want %d (fixed-length r||s)", c.alg, len(sig), c.size)
		}
		v, err := NewECDSAVerifier(c.alg, &c.key.PublicKey, "e1")
		if err != nil {
			t.Fatalf("%s: verifier: %v", c.alg, err)
		}
		if err := v.Verify([]byte("a.b"), sig); err != nil {
			t.Fatalf("%s: verify: %v", c.alg, err)
		}
		if s.Algorithm() != c.alg || v.Algorithm() != c.alg || s.KeyID() != "e1" || v.KeyID() != "e1" {
			t.Fatalf("%s: getters wrong", c.alg)
		}
	}
}

func TestECDSAVerifyRejectsBadSignature(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewECDSASigner(ES256, tk.p256, "")
	v, _ := NewECDSAVerifier(ES256, &tk.p256.PublicKey, "")
	sig, _ := s.Sign([]byte("a.b"))

	// wrong length (e.g. an ASN.1 DER signature, which JWA forbids)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(2)})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify([]byte("a.b"), der); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("DER signature err = %v, want ErrInvalidSignature", err)
	}

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if err := v.Verify([]byte("a.b"), tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered err = %v", err)
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v2, _ := NewECDSAVerifier(ES256, &other.PublicKey, "")
	if err := v2.Verify([]byte("a.b"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong key err = %v", err)
	}
}

func TestECDSARejectsCurveMismatch(t *testing.T) {
	tk := newTestKeys(t)
	if _, err := NewECDSASigner(ES256, tk.p384, ""); !errors.Is(err, ErrKeyTypeMismatch) {
		t.Fatalf("signer curve mismatch err = %v", err)
	}
	if _, err := NewECDSAVerifier(ES512, &tk.p256.PublicKey, ""); !errors.Is(err, ErrKeyTypeMismatch) {
		t.Fatalf("verifier curve mismatch err = %v", err)
	}
}

func TestECDSARejectsWrongAlgorithmOrNilKey(t *testing.T) {
	tk := newTestKeys(t)
	if _, err := NewECDSASigner("bogus", tk.p256, ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("signer bogus alg err = %v", err)
	}
	if _, err := NewECDSAVerifier("bogus", &tk.p256.PublicKey, ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("verifier bogus alg err = %v", err)
	}
	if _, err := NewECDSASigner(ES256, nil, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil signer key err = %v", err)
	}
	if _, err := NewECDSAVerifier(ES256, nil, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil verifier key err = %v", err)
	}
}
