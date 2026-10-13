package jwt

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func BenchmarkV1KeysKeySetLookupAbsent(b *testing.B) {
	keys := make([]Key, 4096)
	for i := range keys {
		keys[i] = FromEd25519PublicKey(make([]byte, 32), "kid-"+strconv.Itoa(i))
	}

	set := NewKeySet(keys...)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _, _ = set.Lookup(ctx, "absent")
	}
}

func BenchmarkV1KeysParseKeySetJWKS(b *testing.B) {
	keys := make([]Key, MaxKeySetKeys)
	for i := range keys {
		keys[i] = FromEd25519PublicKey(make([]byte, 32), "kid-"+strconv.Itoa(i))
	}

	doc, err := json.Marshal(NewKeySet(keys...))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(doc)))
	b.ResetTimer()

	for range b.N {
		if _, err := ParseKeySet(doc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkV1KeysMemoryRevocationStore(b *testing.B) {
	store := NewMemoryRevocationStore()
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	ids := make([]string, 1024)
	for i := range ids {
		ids[i] = "jti-" + strconv.Itoa(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		if err := store.Revoke(ctx, ids[i%len(ids)], ReasonAdmin, expires); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkV1KeysMemoryRevocationStoreLookup(b *testing.B) {
	store := NewMemoryRevocationStore()

	ctx := context.Background()
	if err := store.Revoke(ctx, "revoked", ReasonAdmin, time.Time{}); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _ = store.IsRevoked(ctx, "revoked")
	}
}
