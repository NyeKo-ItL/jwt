package keyparse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	internalerr "github.com/NyeKo-ItL/jwt/internal/errors"
)

func TestDERParsers(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	if _, err := ParsePKCS8PrivateKey(pkcs8); err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	if _, err := ParsePKCS1PrivateKey(pkcs1); err != nil {
		t.Fatal(err)
	}
	sec1, _ := x509.MarshalECPrivateKey(ecKey)
	if _, err := ParseSEC1ECPrivateKey(sec1); err != nil {
		t.Fatal(err)
	}
	pkix, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if _, err := ParsePKIXPublicKey(pkix); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePKCS8PrivateKey([]byte("bad")); !errors.Is(err, internalerr.ErrMalformedKey) {
		t.Fatal(err)
	}
	_ = edPriv
}

func TestEd25519Parsers(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseEd25519PrivateKeySeed(priv.Seed()); err != nil || !got.Equal(priv) {
		t.Fatalf("seed parse: %v", err)
	}
	if got, err := ParseEd25519PrivateKeyExpanded(priv); err != nil || !got.Equal(priv) {
		t.Fatalf("expanded parse: %v", err)
	}
	if got, err := ParseEd25519PublicKey(pub); err != nil || !got.Equal(pub) {
		t.Fatalf("public parse: %v", err)
	}
	if _, err := ParseEd25519PublicKey([]byte("bad")); !errors.Is(err, internalerr.ErrMalformedKey) {
		t.Fatal(err)
	}
}
