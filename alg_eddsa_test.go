package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEd25519RoundTrip(t *testing.T) {
	tk := newTestKeys(t)
	s, err := NewEd25519Signer(tk.edPriv, "o1")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign([]byte("a.b"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewEd25519Verifier(tk.edPub, "o1")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify([]byte("a.b"), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if s.Algorithm() != EdDSA || v.Algorithm() != EdDSA || s.KeyID() != "o1" || v.KeyID() != "o1" {
		t.Fatal("getters wrong")
	}
}

func TestEd25519RejectsBadKeySize(t *testing.T) {
	if _, err := NewEd25519Signer(ed25519.PrivateKey{1, 2, 3}, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short private key err = %v", err)
	}
	if _, err := NewEd25519Verifier(ed25519.PublicKey{1, 2, 3}, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short public key err = %v", err)
	}
}

func TestEd25519VerifyRejectsBadSignature(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewEd25519Signer(tk.edPriv, "")
	v, _ := NewEd25519Verifier(tk.edPub, "")
	sig, _ := s.Sign([]byte("a.b"))

	if err := v.Verify([]byte("a.b"), sig[:10]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("short sig err = %v", err)
	}
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if err := v.Verify([]byte("a.b"), tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered err = %v", err)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	v2, _ := NewEd25519Verifier(otherPub, "")
	if err := v2.Verify([]byte("a.b"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong key err = %v", err)
	}
}
