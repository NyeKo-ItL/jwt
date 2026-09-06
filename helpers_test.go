package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// testKeys holds a freshly generated key of every family, shared across
// tests via testing.T.Helper-style lazy construction.
type testKeys struct {
	rsa2048 *rsa.PrivateKey
	rsa1024 *rsa.PrivateKey
	p256    *ecdsa.PrivateKey
	p384    *ecdsa.PrivateKey
	p521    *ecdsa.PrivateKey
	edPub   ed25519.PublicKey
	edPriv  ed25519.PrivateKey
	hmac    []byte
}

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	var tk testKeys
	var err error
	if tk.rsa2048, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if tk.rsa1024, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		t.Fatal(err)
	}
	if tk.p256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if tk.p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if tk.p521, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if tk.edPub, tk.edPriv, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	tk.hmac = make([]byte, 64)
	if _, err = rand.Read(tk.hmac); err != nil {
		t.Fatal(err)
	}
	return tk
}

// mintToken assembles a compact JWS from an explicit header, an arbitrary
// payload value, and an optional signer (nil signer => empty signature).
func mintToken(t *testing.T, header Header, payload any, signer Signer) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := b64.Encode(hb) + "." + b64.Encode(pb)
	var sig []byte
	if signer != nil {
		if sig, err = signer.Sign([]byte(signingInput)); err != nil {
			t.Fatal(err)
		}
	}
	return signingInput + "." + b64.Encode(sig)
}

// rs256TestSigner is a caller-supplied Signer for an algorithm the library
// has no built-in constructor for (RS256), mirroring the §5.1 KMS example.
type rs256TestSigner struct {
	key *rsa.PrivateKey
	kid string
}

func (s rs256TestSigner) Algorithm() Algorithm { return RS256 }
func (s rs256TestSigner) KeyID() string        { return s.kid }
func (s rs256TestSigner) Sign(signingInput []byte) ([]byte, error) {
	sum := sha256.Sum256(signingInput)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
}

type staticStr struct {
	alg Algorithm
	kid string
}

func (s staticStr) Algorithm() Algorithm          { return s.alg }
func (s staticStr) KeyID() string                 { return s.kid }
func (s staticStr) Sign(_ []byte) ([]byte, error) { return []byte("x"), nil }
