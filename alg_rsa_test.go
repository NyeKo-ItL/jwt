package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestRSAPSSRoundTrip(t *testing.T) {
	tk := newTestKeys(t)
	for _, alg := range []Algorithm{PS256, PS384, PS512} {
		s, err := NewRSAPSSSigner(alg, tk.rsa2048, "r1")
		if err != nil {
			t.Fatalf("%s: signer: %v", alg, err)
		}
		if s.Algorithm() != alg || s.KeyID() != "r1" {
			t.Fatalf("%s: getters wrong", alg)
		}
		sig, err := s.Sign([]byte("a.b"))
		if err != nil {
			t.Fatalf("%s: sign: %v", alg, err)
		}
		v, err := NewRSAPSSVerifier(alg, &tk.rsa2048.PublicKey, "r1")
		if err != nil {
			t.Fatalf("%s: verifier: %v", alg, err)
		}
		if err := v.Verify([]byte("a.b"), sig); err != nil {
			t.Fatalf("%s: verify: %v", alg, err)
		}
		if v.Algorithm() != alg {
			t.Fatalf("%s: verifier alg wrong", alg)
		}
		if err := v.Verify([]byte("a.b"), append(sig, 0)); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("%s: tampered verify err = %v", alg, err)
		}
	}
}

func TestRSAPKCS1VerifyOnly(t *testing.T) {
	tk := newTestKeys(t)
	sum := sha256.Sum256([]byte("a.b"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, tk.rsa2048, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewRSAPKCS1Verifier(RS256, &tk.rsa2048.PublicKey, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify([]byte("a.b"), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := v.Verify([]byte("a.b"), sig[:len(sig)-1]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("truncated verify err = %v", err)
	}
}

func TestRSARejectsWeakKey(t *testing.T) {
	tk := newTestKeys(t)
	if _, err := NewRSAPSSSigner(PS256, tk.rsa1024, ""); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("signer err = %v, want ErrWeakKey", err)
	}
	if _, err := NewRSAPSSVerifier(PS256, &tk.rsa1024.PublicKey, ""); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("pss verifier err = %v, want ErrWeakKey", err)
	}
	if _, err := NewRSAPKCS1Verifier(RS256, &tk.rsa1024.PublicKey, ""); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("pkcs1 verifier err = %v, want ErrWeakKey", err)
	}
}

func TestRSARejectsWrongAlgorithmOrNilKey(t *testing.T) {
	tk := newTestKeys(t)
	if _, err := NewRSAPSSSigner(RS256, tk.rsa2048, ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("PSS signer with RS256: %v", err)
	}
	if _, err := NewRSAPKCS1Verifier(PS256, &tk.rsa2048.PublicKey, ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("PKCS1 verifier with PS256: %v", err)
	}
	if _, err := NewRSAPSSVerifier("bogus", &tk.rsa2048.PublicKey, ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("PSS verifier with bogus alg: %v", err)
	}
	if _, err := NewRSAPSSSigner(PS256, nil, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil signer key: %v", err)
	}
	if _, err := NewRSAPSSVerifier(PS256, nil, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil verifier key: %v", err)
	}
}

func TestRSAPSSVerifyRejectsWrongKey(t *testing.T) {
	tk := newTestKeys(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewRSAPSSSigner(PS256, tk.rsa2048, "")
	sig, _ := s.Sign([]byte("a.b"))
	v, _ := NewRSAPSSVerifier(PS256, &other.PublicKey, "")
	if err := v.Verify([]byte("a.b"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong key verify err = %v", err)
	}
}
