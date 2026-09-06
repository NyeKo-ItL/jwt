package jwt

import (
	"context"
	"testing"
	"time"
)

func TestNewOpaqueToken(t *testing.T) {
	a, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if a.Raw == b.Raw {
		t.Fatal("two fresh tokens collided")
	}
	if a.Hash != Hash(a.Raw) {
		t.Fatal("Hash field does not match Hash(Raw)")
	}
	if len(a.Hash) != 64 {
		t.Fatalf("hash hex length = %d, want 64", len(a.Hash))
	}
	if !Equal(a.Hash, a.Raw) {
		t.Fatal("Equal rejected a matching raw/hash pair")
	}
	if Equal(a.Hash, b.Raw) {
		t.Fatal("Equal accepted a mismatched raw")
	}
}

func TestDeriveOpaqueToken(t *testing.T) {
	got := DeriveOpaqueToken("existing-secret")
	if got.Raw != "existing-secret" {
		t.Fatalf("Raw = %q", got.Raw)
	}
	if got.Hash != Hash("existing-secret") {
		t.Fatal("Hash mismatch")
	}
	if DeriveOpaqueToken("x").Hash != DeriveOpaqueToken("x").Hash {
		t.Fatal("derivation is not deterministic")
	}
	if !Equal(got.Hash, "existing-secret") {
		t.Fatal("Equal should accept the derived raw")
	}
}

func TestEqualRejectsWrongLengthHash(t *testing.T) {
	if Equal("short", "whatever") {
		t.Fatal("Equal accepted a malformed stored hash")
	}
}

func TestNewTokenFamily(t *testing.T) {
	a := NewTokenFamily()
	b := NewTokenFamily()
	if a.ID == "" || a.ID == b.ID {
		t.Fatalf("family IDs not unique: %q %q", a.ID, b.ID)
	}
}

func TestRotationResultZeroValue(t *testing.T) {
	var r RotationResult
	if r.ReuseDetected {
		t.Fatal("zero RotationResult should not signal reuse")
	}
}

func TestMemoryRevocationStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRevocationStore()

	if rev, _ := s.IsRevoked(ctx, "jti-1"); rev {
		t.Fatal("unknown id reported revoked")
	}

	future := time.Now().Add(time.Hour)
	if err := s.Revoke(ctx, "jti-1", ReasonLogout, future); err != nil {
		t.Fatal(err)
	}
	if rev, _ := s.IsRevoked(ctx, "jti-1"); !rev {
		t.Fatal("revoked id reported live")
	}

	// zero expiry == permanent
	if err := s.Revoke(ctx, "kid-x", ReasonKeyCompromised, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if rev, _ := s.IsRevoked(ctx, "kid-x"); !rev {
		t.Fatal("permanent revocation not honored")
	}
}

func TestMemoryRevocationStoreExpiry(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRevocationStore().(*memoryRevocationStore)
	base := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return base }

	_ = s.Revoke(ctx, "family-1", ReasonReuseDetected, base.Add(time.Minute))
	if rev, _ := s.IsRevoked(ctx, "family-1"); !rev {
		t.Fatal("should be revoked before expiry")
	}

	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if rev, _ := s.IsRevoked(ctx, "family-1"); rev {
		t.Fatal("should not be revoked after expiry")
	}
	// read path swept it
	if _, ok := s.items["family-1"]; ok {
		t.Fatal("expired entry not swept on read")
	}

	// write path sweeps entries that expired before this Revoke call
	s.now = func() time.Time { return base }
	_ = s.Revoke(ctx, "old", ReasonAdmin, base.Add(time.Minute))
	s.now = func() time.Time { return base.Add(time.Hour) }
	_ = s.Revoke(ctx, "new", ReasonAdmin, base.Add(2*time.Hour))
	if _, ok := s.items["old"]; ok {
		t.Fatal("expired entry not swept on write")
	}
	if _, ok := s.items["new"]; !ok {
		t.Fatal("live entry wrongly swept")
	}
}
