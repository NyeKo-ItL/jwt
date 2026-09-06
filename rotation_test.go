package jwt

import (
	"context"
	"testing"
	"time"
)

// familyRotator is a caller-side refresh-token rotation implementation built
// only from the shapes the library provides (OpaqueToken, TokenFamily,
// RotationResult) plus an injected RevocationStore. The library itself never
// touches this storage — this test proves RotationResult.ReuseDetected is
// enough to drive family revocation on replay (spec §7.2.5).
type familyRotator struct {
	current map[string]string // family ID -> hash of the live token
	revoke  RevocationStore
}

func newFamilyRotator(store RevocationStore) *familyRotator {
	return &familyRotator{current: map[string]string{}, revoke: store}
}

// issue starts a family with a first token.
func (r *familyRotator) issue(ctx context.Context, fam TokenFamily) (OpaqueToken, error) {
	tok, err := NewOpaqueToken()
	if err != nil {
		return OpaqueToken{}, err
	}
	r.current[fam.ID] = tok.Hash
	return tok, nil
}

// rotate exchanges presentedRaw for a fresh token. Presenting anything other
// than the family's live token is treated as reuse: the whole family is
// revoked and ReuseDetected is set.
func (r *familyRotator) rotate(ctx context.Context, fam TokenFamily, presentedRaw string) (RotationResult, error) {
	if revoked, err := r.revoke.IsRevoked(ctx, fam.ID); err != nil {
		return RotationResult{}, err
	} else if revoked {
		return RotationResult{ReuseDetected: true}, nil
	}
	if !Equal(r.current[fam.ID], presentedRaw) {
		if err := r.revoke.Revoke(ctx, fam.ID, ReasonReuseDetected, time.Time{}); err != nil {
			return RotationResult{}, err
		}
		return RotationResult{ReuseDetected: true}, nil
	}
	next, err := NewOpaqueToken()
	if err != nil {
		return RotationResult{}, err
	}
	r.current[fam.ID] = next.Hash
	return RotationResult{Next: next}, nil
}

func TestRefreshRotationReuseDetection(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRevocationStore()
	rot := newFamilyRotator(store)

	fam := NewTokenFamily()
	if fam.ID == "" {
		t.Fatal("empty family ID")
	}

	t0, err := rot.issue(ctx, fam)
	if err != nil {
		t.Fatal(err)
	}

	// Normal chain: t0 -> t1 -> t2.
	res, err := rot.rotate(ctx, fam, t0.Raw)
	if err != nil || res.ReuseDetected {
		t.Fatalf("first rotation: %+v, %v", res, err)
	}
	t1 := res.Next

	res, err = rot.rotate(ctx, fam, t1.Raw)
	if err != nil || res.ReuseDetected {
		t.Fatalf("second rotation: %+v, %v", res, err)
	}
	t2 := res.Next

	// Replay the already-rotated-away t1: reuse must be detected and the
	// whole family revoked.
	res, err = rot.rotate(ctx, fam, t1.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReuseDetected {
		t.Fatal("replaying a superseded token was not flagged as reuse")
	}
	if revoked, _ := store.IsRevoked(ctx, fam.ID); !revoked {
		t.Fatal("family was not revoked after reuse")
	}

	// Even the currently-live t2 is now worthless: the family is dead.
	res, err = rot.rotate(ctx, fam, t2.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReuseDetected {
		t.Fatal("family revocation did not invalidate the live token")
	}
}
