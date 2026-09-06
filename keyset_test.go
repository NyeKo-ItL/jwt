package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestKeySetAddReplaceRemoveLookup(t *testing.T) {
	tk := newTestKeys(t)
	ctx := context.Background()

	a := FromRSAPublicKey(&tk.rsa2048.PublicKey, "a")
	b := FromECDSAPublicKey(&tk.p256.PublicKey, "b")
	s := NewKeySet(a, b)

	if k, ok, _ := s.Lookup(ctx, "b"); !ok || k.Kty != KeyTypeEC {
		t.Fatalf("lookup b: %v %v", k.Kty, ok)
	}
	if _, ok, _ := s.Lookup(ctx, "missing"); ok {
		t.Fatal("lookup missing returned ok")
	}
	// empty kid is ambiguous with 2 keys
	if _, ok, _ := s.Lookup(ctx, ""); ok {
		t.Fatal("empty kid should be ambiguous with 2 keys")
	}

	// replace-by-kid keeps the count stable
	a2 := FromEd25519PublicKey(tk.edPub, "a")
	s.Add(a2)
	keys, _ := s.Keys(ctx)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after replace, got %d", len(keys))
	}
	if k, _, _ := s.Lookup(ctx, "a"); k.Kty != KeyTypeOKP {
		t.Fatalf("replace did not take effect: %v", k.Kty)
	}

	s.Remove("a")
	if _, ok, _ := s.Lookup(ctx, "a"); ok {
		t.Fatal("remove failed")
	}
	// now a sole key -> empty kid resolves to it
	if _, ok, _ := s.Lookup(ctx, ""); !ok {
		t.Fatal("empty kid should resolve to the sole key")
	}
}

func TestKeySetKeysIsCopy(t *testing.T) {
	tk := newTestKeys(t)
	s := NewKeySet(FromRSAPublicKey(&tk.rsa2048.PublicKey, "a"))
	keys, _ := s.Keys(context.Background())
	keys[0].Kid = "mutated"
	again, _ := s.Keys(context.Background())
	if again[0].Kid != "a" {
		t.Fatal("Keys() exposed internal storage")
	}
}

func TestKeySetMarshalJSON(t *testing.T) {
	tk := newTestKeys(t)
	s := NewKeySet(
		FromRSAPublicKey(&tk.rsa2048.PublicKey, "a"),
		FromECDSAPublicKey(&tk.p256.PublicKey, "b"),
	)
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	round, err := ParseKeySet(raw)
	if err != nil {
		t.Fatal(err)
	}
	if k, ok, _ := round.Lookup(context.Background(), "a"); !ok || k.Kty != KeyTypeRSA {
		t.Fatalf("round trip lost key a: %v %v", k.Kty, ok)
	}

	// an oct key must block the whole document
	s.Add(FromHMACSecret(tk.hmac, "secret"))
	if _, err := json.Marshal(s); !errors.Is(err, ErrOctNotServable) {
		t.Fatalf("marshal with oct key err = %v", err)
	}
}

func TestParseKeySet(t *testing.T) {
	tk := newTestKeys(t)
	good, _ := json.Marshal(NewKeySet(FromRSAPublicKey(&tk.rsa2048.PublicKey, "a")))
	if _, err := ParseKeySet(good); err != nil {
		t.Fatalf("good doc: %v", err)
	}

	for name, doc := range map[string]string{
		"not json":         `{`,
		"no keys array":    `{"foo":1}`,
		"malformed member": `{"keys":[{"kty":"RSA","n":"!!!","e":"AQAB"}]}`,
		"member no kty":    `{"keys":[{"kid":"x"}]}`,
	} {
		if _, err := ParseKeySet([]byte(doc)); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}
