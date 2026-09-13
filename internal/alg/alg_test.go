package alg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
}
