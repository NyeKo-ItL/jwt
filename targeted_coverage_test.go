package jwt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"

	"testing"
	"time"
)

func TestTargetedKeySetCoverage(t *testing.T) {
	ctx := context.Background()
	if got := (*KeySet)(nil).Clone(); got == nil {
		t.Fatal("nil Clone returned nil")
	}

	empty := &KeySet{}
	empty.Add(FromHMACSecret([]byte("0123456789abcdef0123456789abcdef"), "empty-init"))

	set := NewKeySet()
	set.Add(FromHMACSecret([]byte("0123456789abcdef0123456789abcdef")))
	if _, ok, err := set.Lookup(ctx, ""); err != nil || !ok {
		t.Fatalf("sole key lookup: ok=%v err=%v", ok, err)
	}
	set.Remove("absent")
	set.Remove("")
	if _, ok, _ := set.Lookup(ctx, ""); ok {
		t.Fatal("removed key still resolved")
	}
	indexed := NewKeySet(FromEd25519PublicKey(make([]byte, 32), "indexed"))
	indexed.Remove("absent")
	indexed.byKID["bad"] = 99
	if _, ok, _ := indexed.Lookup(ctx, "bad"); ok {
		t.Fatal("invalid index resolved")
	}

	diagnostic := KeySetDiagnostic{Index: 3, Err: ErrMalformedKey}
	if diagnostic.Error() == "" || !errors.Is(diagnostic, ErrMalformedKey) {
		t.Fatal("diagnostic does not expose its cause")
	}

	if _, err := ParseKeySet(bytes.Repeat([]byte("x"), MaxKeySetJSONBytes+1)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("oversized document error = %v", err)
	}
	if _, err := ParseKeySet([]byte(`{"keys":[[]]}`)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("invalid member error = %v", err)
	}
	for _, doc := range [][]byte{[]byte(`{}`), []byte(`[]`)} {
		if _, err := ParseKeySet(doc); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("invalid document %q error = %v", doc, err)
		}
	}
	if _, _, err := ParseKeySetPermissive([]byte(`{"keys":[{"kty":"oct","k":"AQ"}]}`)); err != nil {
		t.Fatalf("oct key parse: %v", err)
	}
	if _, err := ParseKeySet([]byte(`{"keys":[` + string(bytes.Repeat([]byte("x"), MaxJWKJSONBytes+1)) + `]}`)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("oversized member error = %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := NewKeySet(FromECDSAPublicKey(&priv.PublicKey, "ec")).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, diagnostics, err := ParseKeySetPermissive(doc)
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("EC parse: diagnostics=%v err=%v", diagnostics, err)
	}
	if _, ok, _ := parsed.Lookup(ctx, "ec"); !ok {
		t.Fatal("EC key was not parsed")
	}

}

func TestTargetedOpaqueCoverage(t *testing.T) {
	token, err := NewOpaqueToken()
	if err != nil || token.Raw == "" || !VerifyOpaqueTokenHash(token.Hash, token.Raw) {
		t.Fatalf("new opaque token: token=%+v err=%v", token, err)
	}
}

func TestTargetedRevocationCoverage(t *testing.T) {
	if !(revocationExpiryHeap{
		{id: "late", expiresAt: time.Unix(2, 0)},
		{id: "early", expiresAt: time.Unix(1, 0)},
	}).Less(1, 0) {
		t.Fatal("expiry heap is not ordered")
	}

	store := newMemoryRevocationStore(0)
	base := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return base }
	for i := 0; i < 70; i++ {
		if err := store.Revoke(context.Background(), "rotated", ReasonAdmin, base.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.expirations) > 2*len(store.items)+64 {
		t.Fatalf("stale expiry heap was not compacted: %d", len(store.expirations))
	}
	if revoked, err := store.IsRevoked(context.Background(), "rotated"); err != nil || !revoked {
		t.Fatalf("rotated entry: revoked=%v err=%v", revoked, err)
	}
	if err := store.Revoke(context.Background(), "rotated", ReasonAdmin, base.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if revoked, err := store.IsRevoked(context.Background(), "rotated"); err != nil || revoked {
		t.Fatalf("expired replacement: revoked=%v err=%v", revoked, err)
	}
}
