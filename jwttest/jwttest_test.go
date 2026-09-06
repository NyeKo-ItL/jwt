package jwttest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NyeKo-ItL/jwt"
	"github.com/NyeKo-ItL/jwt/jwttest"
)

func TestFakeKeyProvider(t *testing.T) {
	ctx := context.Background()
	k := jwt.FromHMACSecret([]byte("0123456789abcdef0123456789abcdef"), "k1")
	p := jwttest.NewFakeKeyProvider(k)

	if got, ok, err := p.Lookup(ctx, "k1"); !ok || err != nil || got.Kid != "k1" {
		t.Fatalf("Lookup(k1) = %+v, %v, %v", got, ok, err)
	}
	if got, ok, err := p.Lookup(ctx, ""); !ok || err != nil || got.Kid != "k1" {
		t.Fatalf(`Lookup("") = %+v, %v, %v`, got, ok, err)
	}
	if _, ok, _ := p.Lookup(ctx, "missing"); ok {
		t.Fatal("missing kid resolved")
	}

	sentinel := errors.New("store down")
	p.Err = sentinel
	if _, _, err := p.Lookup(ctx, "k1"); !errors.Is(err, sentinel) {
		t.Fatalf("Err not propagated: %v", err)
	}

	// empty kid is ambiguous with two keys
	p2 := jwttest.NewFakeKeyProvider(k, jwt.FromHMACSecret([]byte("0123456789abcdef0123456789abcdefx"), "k2"))
	if _, ok, _ := p2.Lookup(ctx, ""); ok {
		t.Fatal("empty kid should be ambiguous with 2 keys")
	}
}

func TestFakeRevocationStore(t *testing.T) {
	ctx := context.Background()
	base := time.Unix(1_700_000_000, 0)
	s := jwttest.NewFakeRevocationStore()
	s.Now = func() time.Time { return base }

	if rev, _ := s.IsRevoked(ctx, "x"); rev {
		t.Fatal("unknown id revoked")
	}
	_ = s.Revoke(ctx, "x", jwt.ReasonLogout, base.Add(time.Minute))
	if rev, _ := s.IsRevoked(ctx, "x"); !rev {
		t.Fatal("should be revoked before expiry")
	}
	s.Now = func() time.Time { return base.Add(2 * time.Minute) }
	if rev, _ := s.IsRevoked(ctx, "x"); rev {
		t.Fatal("should have expired")
	}

	_ = s.Revoke(ctx, "perm", jwt.ReasonAdmin, time.Time{})
	if rev, _ := s.IsRevoked(ctx, "perm"); !rev {
		t.Fatal("zero expiry should be permanent")
	}

	sentinel := errors.New("redis down")
	s.Err = sentinel
	if err := s.Revoke(ctx, "y", jwt.ReasonLogout, base); !errors.Is(err, sentinel) {
		t.Fatalf("Revoke Err: %v", err)
	}
	if _, err := s.IsRevoked(ctx, "y"); !errors.Is(err, sentinel) {
		t.Fatalf("IsRevoked Err: %v", err)
	}
}

func TestNewSigningPair(t *testing.T) {
	signer, keys := jwttest.NewSigningPair(t, "")
	if signer.Algorithm() != jwt.EdDSA {
		t.Fatalf("alg = %s", signer.Algorithm())
	}
	tok, err := jwt.Sign(jwt.Claims[struct{}]{}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwt.Parse[struct{}](context.Background(), tok, keys, jwt.WithAllowedAlgorithms(jwt.EdDSA)); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

// The conformance runners are also exercised for real from the root module's
// conformance_test.go; run them here against the fakes so this package's own
// coverage reflects them.
func TestConformanceRunnersAgainstFakes(t *testing.T) {
	jwttest.RunKeyProviderConformance(t, "FakeKeyProvider", func(keys ...jwt.Key) jwt.KeyProvider {
		return jwttest.NewFakeKeyProvider(keys...)
	})
	jwttest.RunRevocationStoreConformance(t, "FakeRevocationStore", func() jwt.RevocationStore {
		return jwttest.NewFakeRevocationStore()
	})
}
