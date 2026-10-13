package jwttest_test

import (
	"testing"
	"time"

	"github.com/NyeKo-ItL/jwt"
	"github.com/NyeKo-ItL/jwt/jwttest"
)

func TestFakeRevocationStoreFallbackClockOnExpiringEntry(t *testing.T) {
	s := jwttest.NewFakeRevocationStore()
	s.Now = nil
	if err := s.Revoke(t.Context(), "fallback-expiry", jwt.ReasonLogout, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if revoked, err := s.IsRevoked(t.Context(), "fallback-expiry"); err != nil || !revoked {
		t.Fatalf("fallback clock: revoked=%v err=%v", revoked, err)
	}
}
