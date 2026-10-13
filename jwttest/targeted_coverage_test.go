package jwttest_test

import (
	crand "crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/NyeKo-ItL/jwt/jwttest"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

type recordingTB struct {
	*testing.T
	fatalCalls int
}

func (tb *recordingTB) Helper()               {}
func (tb *recordingTB) Fatalf(string, ...any) { tb.fatalCalls++ }

func TestTargetedJwttestCoverage(t *testing.T) {
	store := jwttest.NewFakeRevocationStore()
	store.Now = nil
	if err := store.Revoke(t.Context(), "fallback-clock", "admin_revoked", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if revoked, err := store.IsRevoked(t.Context(), "fallback-clock"); err != nil || !revoked {
		t.Fatalf("fallback clock: revoked=%v err=%v", revoked, err)
	}

	oldReader := crand.Reader
	crand.Reader = failingReader{}
	tb := &recordingTB{T: t}
	jwttest.NewSigningPair(tb, "broken")
	crand.Reader = oldReader
	if tb.fatalCalls < 2 {
		t.Fatalf("expected key-generation and signer failures, got %d", tb.fatalCalls)
	}
}
