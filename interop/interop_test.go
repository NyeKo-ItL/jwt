// Package interop cross-checks github.com/NyeKo-ItL/jwt against the two
// dominant Go JOSE libraries — github.com/golang-jwt/jwt/v5 and
// github.com/go-jose/go-jose/v4 — for every supported JWS and JWE
// algorithm, in both directions (spec §7.2.2).
//
// It lives in its own module so those dependencies never reach consumers of
// the main package. Run it explicitly: `cd interop && go test ./...`.
package interop

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
)

// keys holds one key per family, generated once for the whole run.
var keys struct {
	hmac   []byte
	rsa    *rsa.PrivateKey
	p256   *ecdsa.PrivateKey
	p384   *ecdsa.PrivateKey
	p521   *ecdsa.PrivateKey
	edPub  ed25519.PublicKey
	edPriv ed25519.PrivateKey
	kek    []byte            // A256KW key-encryption key
	dir    map[string][]byte // pre-shared CEK per content algorithm
}

func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func TestMain(m *testing.M) {
	keys.hmac = mustRandom(64)
	keys.kek = mustRandom(32)
	keys.dir = map[string][]byte{"A128GCM": mustRandom(16), "A192GCM": mustRandom(24), "A256GCM": mustRandom(32)}
	var err error
	if keys.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	if keys.p256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		panic(err)
	}
	if keys.p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		panic(err)
	}
	if keys.p521, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); err != nil {
		panic(err)
	}
	if keys.edPub, keys.edPriv, err = ed25519.GenerateKey(rand.Reader); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
