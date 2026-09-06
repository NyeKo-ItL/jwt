package jwt

import (
	"context"
	"sync"
	"time"
)

// RevocationReason records why an identifier was revoked.
type RevocationReason string

const (
	ReasonLogout         RevocationReason = "logout"
	ReasonKeyCompromised RevocationReason = "key_compromised" // identifier is a ThumbprintBytes-derived kid
	ReasonReuseDetected  RevocationReason = "reuse_detected"  // identifier is a TokenFamily.ID
	ReasonAdmin          RevocationReason = "admin_revoked"
)

// RevocationStore abstracts revocation-state storage, generalized over the
// identifier namespace: the same interface revokes a single token by "jti",
// an entire signing key by its JWK thumbprint, or a refresh-token session by
// TokenFamily.ID. The library ships an in-memory implementation sufficient
// for a single process; real deployments inject a shared store (Redis, a
// database) so revocation is visible across instances and survives restarts.
type RevocationStore interface {
	// Revoke marks id as revoked until expiresAt. A zero expiresAt means the
	// revocation never expires. The caller decides what id denotes.
	Revoke(ctx context.Context, id string, reason RevocationReason, expiresAt time.Time) error
	// IsRevoked reports whether id is currently revoked.
	IsRevoked(ctx context.Context, id string) (bool, error)
}

type revocationEntry struct {
	reason    RevocationReason
	expiresAt time.Time
}

func (e revocationEntry) live(now time.Time) bool {
	return e.expiresAt.IsZero() || e.expiresAt.After(now)
}

// memoryRevocationStore is an in-process, mutex-guarded map with a lazy
// expiry sweep. Not persisted, not shared across instances.
type memoryRevocationStore struct {
	mu    sync.Mutex
	items map[string]revocationEntry
	now   func() time.Time
}

// NewMemoryRevocationStore returns the library's built-in RevocationStore:
// an in-process, mutex-guarded map with lazy expiry. Documented as
// single-process-only.
func NewMemoryRevocationStore() RevocationStore {
	return &memoryRevocationStore{
		items: make(map[string]revocationEntry),
		now:   time.Now,
	}
}

func (s *memoryRevocationStore) Revoke(_ context.Context, id string, reason RevocationReason, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.items { // full sweep on write keeps the map from growing unbounded
		if !e.live(now) {
			delete(s.items, k)
		}
	}
	s.items[id] = revocationEntry{reason: reason, expiresAt: expiresAt}
	return nil
}

func (s *memoryRevocationStore) IsRevoked(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[id]
	if !ok {
		return false, nil
	}
	if !e.live(s.now()) {
		delete(s.items, id)
		return false, nil
	}
	return true, nil
}
