package jwt

import (
	"context"
	"testing"
)

// The fuzz targets assert the spec §4.11 guarantee: no public parsing or
// decryption entry point may panic on malformed, truncated or oversized
// input — it must always return an error instead.

func FuzzParse(f *testing.F) {
	tk := newTestKeys(f)
	signer, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	seed, _ := Sign(Claims[appClaims]{RegisteredClaims: RegisteredClaims{Subject: "seed"}}, signer)
	f.Add(seed)
	f.Add("")
	f.Add("a.b.c")
	f.Add("....")

	keys := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = Parse[appClaims](context.Background(), token, keys, WithAllowedAlgorithms(HS256))
		_, _ = ParseInsecure[appClaims](token)
	})
}

func FuzzDecryptClaims(f *testing.F) {
	tk := newTestKeys(f)
	enc, _ := NewA256KWEncrypter(tk.hmac[:32], A256GCM, "k1")
	seed, _ := EncryptClaims(Claims[appClaims]{RegisteredClaims: RegisteredClaims{Subject: "seed"}}, enc)
	f.Add(seed)
	f.Add("")
	f.Add("a.b.c.d.e")

	dec, _ := NewA256KWDecrypter(tk.hmac[:32], "k1")
	f.Fuzz(func(t *testing.T, compact string) {
		_, _ = DecryptClaims[appClaims](context.Background(), compact, dec)
	})
}

func FuzzParseKeySet(f *testing.F) {
	f.Add(`{"keys":[]}`)
	f.Add(`{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB"}]}`)
	f.Add(`{`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, doc string) {
		_, _ = ParseKeySet([]byte(doc))
		_, _ = ParseKey([]byte(doc))
	})
}
