package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestV1KeysKeySetDeepCopiesEveryBoundary(t *testing.T) {
	ctx := context.Background()
	original := FromHMACSecret([]byte("0123456789abcdef0123456789abcdef"), "k1")
	original.KeyOps = []string{"verify"}
	set := NewKeySet(original)

	original.KeyOps[0] = "mutated"
	original.k[0] ^= 0xff

	got, ok, err := set.Lookup(ctx, "k1")
	if err != nil || !ok {
		t.Fatalf("Lookup: ok=%v err=%v", ok, err)
	}
	if got.KeyOps[0] != "verify" || string(got.k) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("Add retained caller storage: ops=%v key=%q", got.KeyOps, got.k)
	}

	got.KeyOps[0] = "changed"
	got.k[0] ^= 0xff
	again, _, _ := set.Lookup(ctx, "k1")
	if again.KeyOps[0] != "verify" || string(again.k) != "0123456789abcdef0123456789abcdef" {
		t.Fatal("Lookup exposed KeySet storage")
	}

	keys, _ := set.Keys(ctx)
	keys[0].KeyOps[0] = "changed"
	keys[0].k[0] ^= 0xff
	again, _, _ = set.Lookup(ctx, "k1")
	if again.KeyOps[0] != "verify" || string(again.k) != "0123456789abcdef0123456789abcdef" {
		t.Fatal("Keys exposed KeySet storage")
	}

	clone := set.Clone()
	clone.Remove("k1")
	if _, ok, _ := set.Lookup(ctx, "k1"); !ok {
		t.Fatal("Clone shared KeySet state")
	}
}

func TestV1KeysStaticAndMapProvidersDeepCopyKeys(t *testing.T) {
	ctx := context.Background()
	original := FromHMACSecret([]byte("0123456789abcdef0123456789abcdef"), "k1")
	original.KeyOps = []string{"verify"}

	static := StaticKeyProvider(original)
	mapped := MapKeyProvider(map[string]Key{"k1": original})
	original.KeyOps[0] = "mutated"
	original.k[0] ^= 0xff

	for name, provider := range map[string]KeyProvider{"static": static, "map": mapped} {
		t.Run(name, func(t *testing.T) {
			got, ok, err := provider.Lookup(ctx, "k1")
			if err != nil || !ok || got.KeyOps[0] != "verify" || string(got.k) != "0123456789abcdef0123456789abcdef" {
				t.Fatalf("first lookup: key=%+v ok=%v err=%v", got, ok, err)
			}

			got.KeyOps[0] = "changed"
			got.k[0] ^= 0xff
			again, ok, err := provider.Lookup(ctx, "k1")
			if err != nil || !ok || again.KeyOps[0] != "verify" || string(again.k) != "0123456789abcdef0123456789abcdef" {
				t.Fatalf("provider exposed storage: key=%+v ok=%v err=%v", again, ok, err)
			}
		})
	}
}

func TestV1KeysKeySetIndexPreservesOrderOnReplace(t *testing.T) {
	set := NewKeySet(
		FromEd25519PublicKey(make([]byte, 32), "a"),
		FromEd25519PublicKey(make([]byte, 32), "b"),
	)
	replacement := FromEd25519PublicKey(bytesFilled(32, 1), "a")
	set.Add(replacement)

	keys, _ := set.Keys(context.Background())
	if len(keys) != 2 || keys[0].Kid != "a" || keys[1].Kid != "b" || keys[0].x[0] != 1 {
		t.Fatalf("replace changed order or value: %+v", keys)
	}
}

func TestV1KeysParseKeySetStrictAndPermissive(t *testing.T) {
	validX := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	doc := []byte(fmt.Sprintf(`{"keys":[{"kty":"unsupported","kid":"u"},{"kty":"OKP","crv":"Ed25519","x":"bad"},{"kty":"OKP","crv":"Ed25519","x":%q,"kid":"good"}]}`, validX))

	if _, err := ParseKeySet(doc); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("strict ParseKeySet error = %v", err)
	}

	set, diagnostics, err := ParseKeySetPermissive(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 2 || diagnostics[0].Index != 0 || diagnostics[1].Index != 1 {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
	if key, ok, _ := set.Lookup(context.Background(), "good"); !ok || key.Kty != KeyTypeOKP {
		t.Fatalf("valid key was not retained: %+v, %v", key, ok)
	}
}

func TestV1KeysParseKeySetLimits(t *testing.T) {
	validX := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	valid := json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, validX))
	keys := make([]json.RawMessage, MaxKeySetKeys+1)
	for i := range keys {
		keys[i] = valid
	}
	doc, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKeySet(doc); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("key-count limit error = %v", err)
	}

	tooLarge := base64.RawURLEncoding.EncodeToString(make([]byte, MaxJWKMaterialBytes+1))
	materialDoc := []byte(fmt.Sprintf(`{"keys":[{"kty":"oct","k":%q}]}`, tooLarge))
	if _, err := ParseKeySet(materialDoc); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("material limit error = %v", err)
	}

	oversizedN := make([]byte, MaxRSAKeyBits/8+1)
	oversizedN[0] = 1
	oversizedN[len(oversizedN)-1] = 1
	rsaDoc := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","n":%q,"e":"AQAB"}]}`, base64.RawURLEncoding.EncodeToString(oversizedN)))
	if _, err := ParseKeySet(rsaDoc); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("RSA maximum error = %v", err)
	}
}

func TestV1KeysNilAndPartialAsymmetricKeysNeverPanic(t *testing.T) {
	assertNoPanic(t, func() {
		if _, err := FromRSAPublicKey(nil).PublicKey(); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("nil RSA conversion error = %v", err)
		}
	})
	assertNoPanic(t, func() {
		if _, err := FromECDSAPublicKey(nil).PublicKey(); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("nil ECDSA conversion error = %v", err)
		}
	})
	assertNoPanic(t, func() {
		partial := &ecdsa.PrivateKey{}
		if _, err := NewECDSASigner(ES256, partial); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("partial ECDSA private key error = %v", err)
		}
	})
	assertNoPanic(t, func() {
		if _, err := NewECDSAVerifier(ES256, &ecdsa.PublicKey{Curve: elliptic.P256()}); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("partial ECDSA public key error = %v", err)
		}
	})
	assertNoPanic(t, func() {
		partial := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: oddNumberWithBits(2048), E: 65537}, D: big.NewInt(1)}
		if _, err := NewRSAPSSSigner(PS256, partial); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("partial RSA private key error = %v", err)
		}
	})
	assertNoPanic(t, func() {
		if _, err := NewRSAPSSVerifier(PS256, &rsa.PublicKey{}); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("partial RSA public key error = %v", err)
		}
	})

	oversized := &rsa.PublicKey{N: oddNumberWithBits(MaxRSAKeyBits + 1), E: 65537}
	if _, err := NewRSAPSSVerifier(PS256, oversized); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("oversized RSA verifier error = %v", err)
	}
	if _, err := FromRSAPublicKey(oversized).PublicKey(); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("oversized RSA JWK error = %v", err)
	}
}

func TestV1KeysThumbprintsValidateRepresentations(t *testing.T) {
	for _, n := range []int{1, 31, 33} {
		if _, err := ThumbprintBytes(KeyTypeOKP, make([]byte, n)); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("OKP length %d error = %v", n, err)
		}
	}

	invalidEC := Key{Kty: KeyTypeEC, crv: "P-256", x: make([]byte, 32), y: make([]byte, 32)}
	if _, err := Thumbprint(invalidEC); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("invalid EC thumbprint error = %v", err)
	}

	invalidRSA := Key{Kty: KeyTypeRSA, n: []byte{4}, e: []byte{3}}
	if _, err := Thumbprint(invalidRSA); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("invalid RSA thumbprint error = %v", err)
	}
}

func TestV1KeysRejectMixedKeyOperationsWithoutUse(t *testing.T) {
	x := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, ops := range []string{
		`["verify","encrypt"]`,
		`["verify","deriveKey"]`,
		`["encrypt","deriveBits"]`,
	} {
		raw := []byte(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"key_ops":%s}`, x, ops))
		if _, err := ParseKey(raw); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("key_ops %s error = %v", ops, err)
		}
	}
}

func TestV1KeysECDSARFC6979Vector(t *testing.T) {
	privateBytes, _ := hex.DecodeString("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewECDSASigner(ES256, key)
	if err != nil {
		t.Fatal(err)
	}

	got, err := signer.Sign([]byte("sample"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(
		"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716" +
			"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
	)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("RFC6979 signature = %X, want %X", got, want)
	}

	again, err := signer.Sign([]byte("sample"))
	if err != nil || hex.EncodeToString(again) != hex.EncodeToString(got) {
		t.Fatalf("signature is not deterministic: %X, %v", again, err)
	}
}

func TestV1KeysRevocationValidationCapacityAndHeapExpiry(t *testing.T) {
	ctx := context.Background()
	if err := NewMemoryRevocationStore().Revoke(ctx, "", ReasonAdmin, time.Time{}); !errors.Is(err, ErrInvalidRevocationID) {
		t.Fatalf("empty Revoke error = %v", err)
	}
	if _, err := NewMemoryRevocationStore().IsRevoked(ctx, ""); !errors.Is(err, ErrInvalidRevocationID) {
		t.Fatalf("empty IsRevoked error = %v", err)
	}
	if _, err := NewMemoryRevocationStoreWithCapacity(0); !errors.Is(err, ErrInvalidRevocationCapacity) {
		t.Fatalf("zero capacity error = %v", err)
	}

	bounded, err := NewMemoryRevocationStoreWithCapacity(2)
	if err != nil {
		t.Fatal(err)
	}
	store := bounded.(*memoryRevocationStore)
	base := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return base }
	if err := store.Revoke(ctx, "a", ReasonAdmin, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, "b", ReasonAdmin, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, "c", ReasonAdmin, time.Time{}); !errors.Is(err, ErrRevocationStoreFull) {
		t.Fatalf("full store error = %v", err)
	}

	store.now = func() time.Time { return base.Add(2 * time.Minute) }
	if err := store.Revoke(ctx, "c", ReasonAdmin, time.Time{}); err != nil {
		t.Fatalf("expired slot was not reclaimed: %v", err)
	}
	if _, ok := store.items["a"]; ok {
		t.Fatal("heap cleanup retained expired entry")
	}
}

func TestV1KeysOpaqueExplicitAPIAndRedaction(t *testing.T) {
	const raw = "super-secret-opaque-value"
	token := OpaqueTokenFromRaw(raw)
	if token.Hash != HashOpaqueToken(raw) || !VerifyOpaqueTokenHash(token.Hash, raw) {
		t.Fatal("explicit opaque-token helpers disagree")
	}

	for _, rendered := range []string{
		fmt.Sprintf("%v", token),
		fmt.Sprintf("%+v", token),
		fmt.Sprintf("%#v", token),
	} {
		if strings.Contains(rendered, raw) || !strings.Contains(rendered, "<redacted>") {
			t.Fatalf("opaque token was not redacted: %s", rendered)
		}
	}
}

func assertNoPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("panicked: %v", recovered)
		}
	}()
	fn()
}

func oddNumberWithBits(bits int) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return n.SetBit(n, 0, 1)
}

func bytesFilled(n int, value byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}
