package jwt

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

func TestStaticKeyProviderKidMismatch(t *testing.T) {
	prov := StaticKeyProvider(Key{Kty: KeyTypeOct, Kid: "a"})
	if _, ok, _ := prov.Lookup(ctx(), "b"); ok {
		t.Fatal("expected miss for non-matching kid")
	}
	if _, ok, _ := prov.Lookup(ctx(), "a"); !ok {
		t.Fatal("expected hit for matching kid")
	}
	if _, ok, _ := prov.Lookup(ctx(), ""); !ok {
		t.Fatal("expected hit for empty requested kid")
	}
}

func TestVerifierKeyIDGetters(t *testing.T) {
	tk := newTestKeys(t)
	v, err := NewRSAPKCS1Verifier(RS256, &tk.rsa2048.PublicKey, "kid-9")
	if err != nil {
		t.Fatal(err)
	}
	if v.KeyID() != "kid-9" {
		t.Fatalf("KeyID = %q", v.KeyID())
	}
}

func TestKeyUnmarshalRejectsBadFields(t *testing.T) {
	for _, doc := range []string{
		`{"kty":"RSA","n":"AQAB","e":"!!"}`,
		`{"kty":"EC","crv":"P-256","x":"!!","y":"AQAB"}`,
		`{"kty":"EC","crv":"P-256","x":"AQAB","y":"!!"}`,
		`{"kty":"oct","k":"!!"}`,
	} {
		var k Key
		if err := json.Unmarshal([]byte(doc), &k); err == nil {
			t.Fatalf("expected error for %s", doc)
		}
	}
}

func TestPublicKeyRejectsOversizeRSAExponent(t *testing.T) {
	k := Key{Kty: KeyTypeRSA, n: []byte{1, 2, 3}, e: []byte{1, 2, 3, 4, 5}}
	if _, err := k.PublicKey(); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("err = %v, want ErrMalformedKey", err)
	}
	k2 := Key{Kty: KeyTypeRSA, n: []byte{1, 2, 3}, e: []byte{0, 0}}
	if _, err := k2.PublicKey(); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("zero exponent err = %v, want ErrMalformedKey", err)
	}
}

func TestSecretRejectsEmptyOct(t *testing.T) {
	k := Key{Kty: KeyTypeOct}
	if _, err := k.Secret(); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("err = %v, want ErrMalformedKey", err)
	}
}

func TestVerifierForAlgPropagatesMalformedKey(t *testing.T) {
	cases := []struct {
		key Key
		alg Algorithm
	}{
		{Key{Kty: KeyTypeRSA}, PS256},
		{Key{Kty: KeyTypeRSA}, RS256},
		{Key{Kty: KeyTypeEC}, ES256},
		{Key{Kty: KeyTypeOKP}, EdDSA},
	}
	for _, c := range cases {
		if _, err := c.key.verifierForAlg(c.alg); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("%s: err = %v, want ErrMalformedKey", c.alg, err)
		}
	}
}

func TestSignPropagatesMarshalAndSignerErrors(t *testing.T) {
	// custom payload that cannot be JSON-marshaled
	if _, err := Sign(make(chan int), staticStr{alg: HS256}); err == nil {
		t.Fatal("expected marshal error")
	}
	// signer whose Sign fails
	if _, err := Sign(appClaims{}, failingSigner{}); !errors.Is(err, errSignBoom) {
		t.Fatalf("err = %v, want errSignBoom", err)
	}
}

var errSignBoom = errors.New("sign boom")

type failingSigner struct{}

func (failingSigner) Algorithm() Algorithm        { return HS256 }
func (failingSigner) KeyID() string               { return "" }
func (failingSigner) Sign([]byte) ([]byte, error) { return nil, errSignBoom }

func TestSignPropagatesRegisteredClaimsMarshalError(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	// An oct key embedded in cnf.jwk makes the claims value unmarshalable.
	oct := FromHMACSecret([]byte("secret"), "h1")
	c := appClaims{RegisteredClaims: RegisteredClaims{Confirmation: &Confirmation{JWK: &oct}}}
	if _, err := Sign(c, s); !errors.Is(err, ErrOctNotServable) {
		t.Fatalf("err = %v, want ErrOctNotServable", err)
	}
}

func TestParseInsecureRejectsBadPayloadJSON(t *testing.T) {
	tok := "aa." + b64.Encode([]byte("not json"))
	if _, err := parseInsecure[appClaims](tok); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("err = %v, want ErrMalformedToken", err)
	}
}

func TestKeyUnmarshalRejectsInvalidJSON(t *testing.T) {
	var k Key
	// Call the method directly: encoding/json rejects a syntactically invalid
	// document before it ever reaches a custom UnmarshalJSON.
	if err := k.UnmarshalJSON([]byte("{not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCurveNameUnknown(t *testing.T) {
	if got := curveName(nil); got != "" {
		t.Fatalf("curveName(nil) = %q, want empty", got)
	}
	if got := curveByName("P-999"); got != nil {
		t.Fatalf("curveByName(P-999) = %v, want nil", got)
	}
}

func TestLeftPad(t *testing.T) {
	if got := leftPad([]byte{1, 2, 3}, 2); len(got) != 3 {
		t.Fatalf("no-op path: len = %d, want 3", len(got))
	}
	got := leftPad([]byte{9}, 4)
	if len(got) != 4 || got[0] != 0 || got[3] != 9 {
		t.Fatalf("pad path: %v", got)
	}
}

func TestParseRejectsPayloadNotMatchingC(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	// {} passes RegisteredClaims validation but cannot unmarshal into an int.
	tok, err := Sign(struct{}{}, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse[int](ctx(), tok, prov, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("err = %v, want ErrMalformedToken", err)
	}
}
