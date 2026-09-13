package alg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestFamilyOf(t *testing.T) {
	cases := map[string]Family{
		"HS256":  FamilyHMAC,
		"PS384":  FamilyRSAPSS,
		"RS512":  FamilyRSAPKCS1,
		"ES256":  FamilyECDSA,
		"EdDSA":  FamilyEdDSA,
		"custom": FamilyUnknown,
	}
	for name, want := range cases {
		if got := FamilyOf(name); got != want {
			t.Errorf("FamilyOf(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestHash(t *testing.T) {
	for _, tc := range []struct {
		name string
		want crypto.Hash
	}{
		{"HS256", crypto.SHA256},
		{"RS384", crypto.SHA384},
		{"PS512", crypto.SHA512},
	} {
		got, ok := Hash(tc.name)
		if !ok || got != tc.want {
			t.Errorf("Hash(%q) = (%v, %t), want (%v, true)", tc.name, got, ok, tc.want)
		}
	}

	if _, ok := Hash("custom"); ok {
		t.Error("Hash(custom) unexpectedly succeeded")
	}
}

func TestAlgorithmPredicatesAndECDSAParams(t *testing.T) {
	if !IsPSS("PS256") || IsPSS("RS256") {
		t.Error("unexpected PSS classification")
	}

	if !IsPKCS1("RS256") || IsPKCS1("PS256") {
		t.Error("unexpected PKCS#1 classification")
	}

	for _, tc := range []struct {
		name string
		size int
	}{
		{"ES256", 32},
		{"ES384", 48},
		{"ES512", 66},
	} {
		curve, hash, size, ok := ECDSAParams(tc.name)
		if !ok || curve == nil || hash == 0 || size != tc.size {
			t.Errorf("ECDSAParams(%q) = (%v, %v, %d, %t)", tc.name, curve, hash, size, ok)
		}
	}

	if _, _, _, ok := ECDSAParams("custom"); ok {
		t.Error("ECDSAParams(custom) unexpectedly succeeded")
	}
}

func TestHashSum(t *testing.T) {
	got := HashSum(crypto.SHA256, []byte("hello"))
	if len(got) != crypto.SHA256.Size() {
		t.Fatalf("HashSum length = %d, want %d", len(got), crypto.SHA256.Size())
	}
}

func TestHMACRoundTrip(t *testing.T) {
	key := make([]byte, 32)

	s, err := NewHMACSigner(HS256, key, "h1")
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewHMACVerifier(HS256, key, "h1")
	if err != nil {
		t.Fatal(err)
	}

	sig, err := s.Sign([]byte("input"))
	if err != nil || v.Verify([]byte("input"), sig) != nil {
		t.Fatalf("HMAC round trip failed: %v", err)
	}
}

func TestEd25519RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewEd25519Signer(priv, "e1")
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewEd25519Verifier(pub, "e1")
	if err != nil {
		t.Fatal(err)
	}

	sig, _ := s.Sign([]byte("input"))
	if v.Verify([]byte("input"), sig) != nil {
		t.Fatal("Ed25519 round trip failed")
	}
}

func TestECDSARoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewECDSASigner(ES256, key)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewECDSAVerifier(ES256, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	sig, _ := s.Sign([]byte("input"))
	if v.Verify([]byte("input"), sig) != nil {
		t.Fatal("ECDSA round trip failed")
	}
}

func TestHMACRejectsInvalidInputs(t *testing.T) {
	if _, err := NewHMACSigner("custom", make([]byte, 32)); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported HMAC algorithm: %v", err)
	}

	if _, err := NewHMACSigner(HS256, make([]byte, 31)); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("short HMAC key: %v", err)
	}

	s, _ := NewHMACSigner(HS256, make([]byte, 32))

	v, _ := NewHMACVerifier(HS256, make([]byte, 32))
	if s.Algorithm() != HS256 || s.KeyID() != "" || v.KeyID() != "" {
		t.Fatal("HMAC metadata mismatch")
	}

	if err := v.Verify([]byte("input"), []byte("bad")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("invalid HMAC signature: %v", err)
	}
}

func TestECDSARejectsInvalidInputs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewECDSASigner("custom", key); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported ECDSA algorithm: %v", err)
	}

	if _, err := NewECDSASigner(ES256, nil); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil ECDSA signer key: %v", err)
	}

	if _, err := NewECDSAVerifier(ES256, nil); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil ECDSA verifier key: %v", err)
	}

	v, _ := NewECDSAVerifier(ES256, &key.PublicKey, "e1")
	if v.Algorithm() != ES256 || v.KeyID() != "e1" {
		t.Fatal("ECDSA metadata mismatch")
	}

	if err := v.Verify([]byte("input"), []byte("bad")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("invalid ECDSA signature: %v", err)
	}
}

func TestRSARoundTrips(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("input")

	pssSigner, err := NewRSAPSSSigner(PS256, key)
	if err != nil {
		t.Fatal(err)
	}

	pssVerifier, err := NewRSAPSSVerifier(PS256, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	sig, _ := pssSigner.Sign(input)
	if pssVerifier.Verify(input, sig) != nil {
		t.Fatal("RSA-PSS round trip failed")
	}

	pkcsVerifier, err := NewRSAPKCS1Verifier(RS256, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(input)

	pkcsSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil || pkcsVerifier.Verify(input, pkcsSig) != nil {
		t.Fatalf("RSA PKCS#1 verification failed: %v", err)
	}

	if pssSigner.Algorithm() != PS256 || pssSigner.KeyID() != "" || pkcsVerifier.Algorithm() != RS256 {
		t.Fatal("RSA metadata mismatch")
	}

	bad := append([]byte(nil), sig...)
	bad[0] ^= 1

	if err := pssVerifier.Verify(input, bad); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("invalid RSA-PSS signature: %v", err)
	}
}

func TestRSARejectsInvalidInputs(t *testing.T) {
	//nolint:gosec // Deliberately exercise rejection of weak RSA keys.
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewRSAPSSSigner(PS256, weak); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("weak RSA signer key: %v", err)
	}

	if _, err := NewRSAPSSSigner("custom", weak); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported RSA signer algorithm: %v", err)
	}

	if _, err := NewRSAPSSVerifier(PS256, &weak.PublicKey); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("weak RSA verifier key: %v", err)
	}

	// Keep each invalid-constructor assertion visually isolated.
	if _, err := NewRSAPKCS1Verifier("custom", &weak.PublicKey); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported RSA verifier algorithm: %v", err)
	}

	if _, err := NewRSAPSSVerifier(PS256, nil); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil RSA verifier key: %v", err)
	}
}

func TestEd25519RejectsInvalidInputs(t *testing.T) {
	if _, err := NewEd25519Signer(ed25519.PrivateKey{1, 2, 3}); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short Ed25519 signer key: %v", err)
	}

	if _, err := NewEd25519Verifier(ed25519.PublicKey{1, 2, 3}); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short Ed25519 verifier key: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	v, _ := NewEd25519Verifier(pub, "e1")
	if v.Algorithm() != EdDSA || v.KeyID() != "e1" {
		t.Fatal("Ed25519 metadata mismatch")
	}

	s, _ := NewEd25519Signer(priv)

	sig, _ := s.Sign([]byte("input"))
	if err := v.Verify([]byte("input"), append(sig, 0)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("invalid Ed25519 signature: %v", err)
	}
}
