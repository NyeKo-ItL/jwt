// Command refresh_rotation demonstrates opaque refresh-token rotation with
// reuse detection: the library supplies the shapes (OpaqueToken,
// TokenFamily, RotationResult) and a RevocationStore; the rotation policy
// and storage are the application's.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/NyeKo-ItL/jwt"
)

// rotator keeps, per family, the hash of the single live token. Presenting
// anything else is reuse: revoke the whole family.
type rotator struct {
	live   map[string]string // family ID -> live token hash
	revoke jwt.RevocationStore
}

func (r *rotator) issue(fam jwt.TokenFamily) (jwt.OpaqueToken, error) {
	tok, err := jwt.NewOpaqueToken()
	if err != nil {
		return jwt.OpaqueToken{}, err
	}
	r.live[fam.ID] = tok.Hash // persist only the hash
	return tok, nil
}

func (r *rotator) rotate(ctx context.Context, fam jwt.TokenFamily, presented string) (jwt.RotationResult, error) {
	if revoked, err := r.revoke.IsRevoked(ctx, fam.ID); err != nil {
		return jwt.RotationResult{}, err
	} else if revoked {
		return jwt.RotationResult{ReuseDetected: true}, nil
	}
	if !jwt.Equal(r.live[fam.ID], presented) {
		// a superseded (or forged) token — burn the family permanently
		_ = r.revoke.Revoke(ctx, fam.ID, jwt.ReasonReuseDetected, time.Time{})
		return jwt.RotationResult{ReuseDetected: true}, nil
	}
	next, err := jwt.NewOpaqueToken()
	if err != nil {
		return jwt.RotationResult{}, err
	}
	r.live[fam.ID] = next.Hash
	return jwt.RotationResult{Next: next}, nil
}

func main() {
	ctx := context.Background()
	r := &rotator{live: map[string]string{}, revoke: jwt.NewMemoryRevocationStore()}

	fam := jwt.NewTokenFamily()
	t0, err := r.issue(fam)
	if err != nil {
		log.Fatal(err)
	}

	res, _ := r.rotate(ctx, fam, t0.Raw)
	t1 := res.Next
	fmt.Printf("t0 -> t1 (reuse=%v)\n", res.ReuseDetected)

	res, _ = r.rotate(ctx, fam, t1.Raw)
	t2 := res.Next
	fmt.Printf("t1 -> t2 (reuse=%v)\n", res.ReuseDetected)

	res, _ = r.rotate(ctx, fam, t1.Raw) // replay a superseded token
	fmt.Printf("replay t1 -> reuse=%v (family now revoked)\n", res.ReuseDetected)

	res, _ = r.rotate(ctx, fam, t2.Raw) // even the live token is dead now
	fmt.Printf("present t2 -> reuse=%v (family is dead)\n", res.ReuseDetected)
}
