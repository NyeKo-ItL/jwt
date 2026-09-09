package jwt_test

import (
	"testing"

	"github.com/NyeKo-ItL/jwt"
	"github.com/NyeKo-ItL/jwt/jwttest"
)

// These run the shared jwttest conformance suites against every built-in
// implementation and against jwttest's own minimal fakes, proving that
// Parse- and revocation-facing behaviour does not depend on which
// implementation is injected (spec §7.2.6).

func TestKeyProviderConformance(t *testing.T) {
	jwttest.RunKeyProviderConformance(t, "KeySet", func(keys ...jwt.Key) jwt.KeyProvider {
		return jwt.NewKeySet(keys...)
	})
	jwttest.RunKeyProviderConformance(t, "MapKeyProvider", func(keys ...jwt.Key) jwt.KeyProvider {
		m := make(map[string]jwt.Key, len(keys))
		for _, k := range keys {
			m[k.Kid] = k
		}
		return jwt.MapKeyProvider(m)
	})
	jwttest.RunKeyProviderConformance(t, "FakeKeyProvider", func(keys ...jwt.Key) jwt.KeyProvider {
		return jwttest.NewFakeKeyProvider(keys...)
	})
}

func TestRevocationStoreConformance(t *testing.T) {
	jwttest.RunRevocationStoreConformance(t, "MemoryRevocationStore", jwt.NewMemoryRevocationStore)
	jwttest.RunRevocationStoreConformance(t, "FakeRevocationStore", func() jwt.RevocationStore {
		return jwttest.NewFakeRevocationStore()
	})
}

// TestFakesPluggableIntoParse checks the jwttest signing pair is drop-in:
// its signer's token verifies through Parse against its matching provider.
func TestFakesPluggableIntoParse(t *testing.T) {
	signer, keys := jwttest.NewSigningPair(t, "kid-1")

	tok, err := jwt.Sign(jwt.RegisteredClaims{Subject: "u1"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	var got jwt.RegisteredClaims
	if err := jwt.Parse(t.Context(), tok, &got, keys, jwt.WithAllowedAlgorithms(jwt.EdDSA)); err != nil {
		t.Fatalf("Parse via jwttest pair: %v", err)
	}
	if got.Subject != "u1" {
		t.Fatalf("subject = %q", got.Subject)
	}
}
