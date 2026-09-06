// Package jwttest provides fakes and shared conformance suites for code that
// plugs into the jwt package's injectable interfaces — so callers need not
// re-implement jwt.KeyProvider / jwt.RevocationStore nor re-derive the
// behaviour Parse and the revocation helpers expect.
//
// It is a separate import path: depending on github.com/NyeKo-ItL/jwt does
// not pull this package (or its testing import) into a consumer binary.
package jwttest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/NyeKo-ItL/jwt"
)

// FakeKeyProvider is a minimal in-memory jwt.KeyProvider, deliberately
// independent of the built-in jwt.KeySet, for exercising Parse against a
// caller-supplied implementation. Setting Err makes every Lookup fail.
type FakeKeyProvider struct {
	Keys map[string]jwt.Key
	Err  error
}

// NewFakeKeyProvider returns a FakeKeyProvider seeded with keys, indexed by
// their Kid.
func NewFakeKeyProvider(keys ...jwt.Key) *FakeKeyProvider {
	m := make(map[string]jwt.Key, len(keys))
	for _, k := range keys {
		m[k.Kid] = k
	}
	return &FakeKeyProvider{Keys: m}
}

// Lookup implements jwt.KeyProvider. An empty kid resolves to the sole key
// when exactly one is held.
func (f *FakeKeyProvider) Lookup(_ context.Context, kid string) (jwt.Key, bool, error) {
	if f.Err != nil {
		return jwt.Key{}, false, f.Err
	}
	if kid == "" {
		if len(f.Keys) == 1 {
			for _, k := range f.Keys {
				return k, true, nil
			}
		}
		return jwt.Key{}, false, nil
	}
	k, ok := f.Keys[kid]
	return k, ok, nil
}

type fakeRevocationEntry struct {
	reason    jwt.RevocationReason
	expiresAt time.Time
}

// FakeRevocationStore is a minimal in-memory jwt.RevocationStore with an
// injectable clock (Now) and error (Err), independent of the built-in
// implementation.
type FakeRevocationStore struct {
	mu      sync.Mutex
	entries map[string]fakeRevocationEntry
	Now     func() time.Time
	Err     error
}

// NewFakeRevocationStore returns an empty FakeRevocationStore using the wall
// clock.
func NewFakeRevocationStore() *FakeRevocationStore {
	return &FakeRevocationStore{entries: map[string]fakeRevocationEntry{}, Now: time.Now}
}

// Revoke implements jwt.RevocationStore.
func (f *FakeRevocationStore) Revoke(_ context.Context, id string, reason jwt.RevocationReason, expiresAt time.Time) error {
	if f.Err != nil {
		return f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[id] = fakeRevocationEntry{reason: reason, expiresAt: expiresAt}
	return nil
}

// IsRevoked implements jwt.RevocationStore. A zero expiresAt never expires.
func (f *FakeRevocationStore) IsRevoked(_ context.Context, id string) (bool, error) {
	if f.Err != nil {
		return false, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[id]
	if !ok {
		return false, nil
	}
	if !e.expiresAt.IsZero() && !e.expiresAt.After(f.now()) {
		delete(f.entries, id)
		return false, nil
	}
	return true, nil
}

func (f *FakeRevocationStore) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// NewSigningPair returns an Ed25519 jwt.Signer and a jwt.KeyProvider that
// verifies its tokens, so tests of higher-level code (middleware, handlers)
// need no key-generation boilerplate. kid may be "".
func NewSigningPair(tb testing.TB, kid string) (jwt.Signer, jwt.KeyProvider) {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("jwttest: generate key: %v", err)
	}
	signer, err := jwt.NewEd25519Signer(priv, kid)
	if err != nil {
		tb.Fatalf("jwttest: new signer: %v", err)
	}
	return signer, jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(pub, kid))
}

// RunKeyProviderConformance runs the shared jwt.KeyProvider behaviour suite
// against newProvider, which must build a provider holding exactly the given
// keys. Run it against every implementation (built-in or custom) to prove
// the Parse-facing behaviour is identical regardless of which one is
// injected.
func RunKeyProviderConformance(t *testing.T, name string, newProvider func(keys ...jwt.Key) jwt.KeyProvider) {
	t.Helper()
	ctx := context.Background()
	k1 := jwt.FromHMACSecret([]byte("k1-secret-k1-secret-k1-secret-32b"), "k1")
	k2 := jwt.FromHMACSecret([]byte("k2-secret-k2-secret-k2-secret-32b"), "k2")

	t.Run(name+"/lookup by kid", func(t *testing.T) {
		got, ok, err := newProvider(k1, k2).Lookup(ctx, "k2")
		if err != nil || !ok || got.Kid != "k2" {
			t.Fatalf("Lookup(k2) = %+v, %v, %v", got, ok, err)
		}
	})
	t.Run(name+"/miss is (false, nil)", func(t *testing.T) {
		_, ok, err := newProvider(k1).Lookup(ctx, "absent")
		if ok || err != nil {
			t.Fatalf("Lookup(absent) = _, %v, %v; want false, nil", ok, err)
		}
	})
	t.Run(name+"/empty kid resolves a sole key", func(t *testing.T) {
		got, ok, err := newProvider(k1).Lookup(ctx, "")
		if err != nil || !ok || got.Kid != "k1" {
			t.Fatalf(`Lookup("") = %+v, %v, %v`, got, ok, err)
		}
	})
}

// RunRevocationStoreConformance runs the shared jwt.RevocationStore
// behaviour suite against newStore (called once per sub-test for isolation).
func RunRevocationStoreConformance(t *testing.T, name string, newStore func() jwt.RevocationStore) {
	t.Helper()
	ctx := context.Background()

	t.Run(name+"/unknown id is not revoked", func(t *testing.T) {
		rev, err := newStore().IsRevoked(ctx, "nope")
		if rev || err != nil {
			t.Fatalf("IsRevoked = %v, %v", rev, err)
		}
	})
	t.Run(name+"/revoked until a future time", func(t *testing.T) {
		s := newStore()
		if err := s.Revoke(ctx, "jti-1", jwt.ReasonLogout, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if rev, err := s.IsRevoked(ctx, "jti-1"); !rev || err != nil {
			t.Fatalf("IsRevoked = %v, %v", rev, err)
		}
	})
	t.Run(name+"/already-expired revocation is inert", func(t *testing.T) {
		s := newStore()
		_ = s.Revoke(ctx, "jti-2", jwt.ReasonLogout, time.Now().Add(-time.Hour))
		if rev, _ := s.IsRevoked(ctx, "jti-2"); rev {
			t.Fatal("an expired revocation is still reported")
		}
	})
	t.Run(name+"/zero expiry is permanent", func(t *testing.T) {
		s := newStore()
		_ = s.Revoke(ctx, "kid-x", jwt.ReasonKeyCompromised, time.Time{})
		if rev, _ := s.IsRevoked(ctx, "kid-x"); !rev {
			t.Fatal("a zero-expiry revocation is not honoured")
		}
	})
}
