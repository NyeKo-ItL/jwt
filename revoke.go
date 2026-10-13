package jwt

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RevocationReason records why an identifier was revoked.
type RevocationReason string

// Revocation reasons recorded with RevocationStore.Revoke.
const (
	ReasonLogout         RevocationReason = "logout"          // identifier is usually a "jti" or session ID
	ReasonKeyCompromised RevocationReason = "key_compromised" // identifier is usually a JWK thumbprint
	ReasonReuseDetected  RevocationReason = "reuse_detected"  // identifier is a TokenFamily.ID
	ReasonAdmin          RevocationReason = "admin_revoked"   // any identifier, revoked by an operator
)

var (
	// ErrInvalidRevocationID reports an empty identifier. Empty IDs are never
	// accepted because they collapse unrelated tokens into one namespace entry.
	ErrInvalidRevocationID = errors.New("jwt: revocation id must not be empty")
	// ErrInvalidRevocationCapacity reports a non-positive bounded capacity.
	ErrInvalidRevocationCapacity = errors.New("jwt: revocation capacity must be positive")
	// ErrRevocationStoreFull reports that a bounded store cannot safely retain
	// another live revocation. Live revocations are never silently evicted.
	ErrRevocationStoreFull = errors.New("jwt: revocation store capacity reached")
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
	reason     RevocationReason
	expiresAt  time.Time
	generation uint64
}

func (e revocationEntry) live(now time.Time) bool {
	return e.expiresAt.IsZero() || e.expiresAt.After(now)
}

type revocationExpiry struct {
	id         string
	expiresAt  time.Time
	generation uint64
}

type revocationExpiryHeap []revocationExpiry

func (h revocationExpiryHeap) Len() int           { return len(h) }
func (h revocationExpiryHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h revocationExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *revocationExpiryHeap) Push(x any)        { *h = append(*h, x.(revocationExpiry)) }
func (h *revocationExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = revocationExpiry{}
	*h = old[:n-1]

	return x
}

// memoryRevocationStore is an in-process, mutex-guarded map with a min-heap
// for amortized expiry cleanup. It is not persisted or shared across instances.
type memoryRevocationStore struct {
	mu          sync.Mutex
	items       map[string]revocationEntry
	expirations revocationExpiryHeap
	now         func() time.Time
	capacity    int // zero means unbounded
	generation  uint64
}

// NewMemoryRevocationStore returns an unbounded, single-process
// RevocationStore. Expiry cleanup is heap-based and amortized rather than a
// full map sweep on each write.
func NewMemoryRevocationStore() RevocationStore {
	return newMemoryRevocationStore(0)
}

// NewMemoryRevocationStoreWithCapacity returns a bounded, single-process
// RevocationStore. capacity must be positive. Revoke returns
// ErrRevocationStoreFull instead of evicting a live revocation when full.
func NewMemoryRevocationStoreWithCapacity(capacity int) (RevocationStore, error) {
	if capacity <= 0 {
		return nil, ErrInvalidRevocationCapacity
	}

	return newMemoryRevocationStore(capacity), nil
}

func newMemoryRevocationStore(capacity int) *memoryRevocationStore {
	return &memoryRevocationStore{
		items:    make(map[string]revocationEntry),
		now:      time.Now,
		capacity: capacity,
	}
}

func (s *memoryRevocationStore) Revoke(_ context.Context, id string, reason RevocationReason, expiresAt time.Time) error {
	if id == "" {
		return ErrInvalidRevocationID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.removeExpiredLocked(now)

	// An already-expired revocation is inert. If it replaces an existing ID,
	// removing that ID matches the requested expiry state.
	if !expiresAt.IsZero() && !expiresAt.After(now) {
		delete(s.items, id)
		return nil
	}

	if _, exists := s.items[id]; !exists && s.capacity > 0 && len(s.items) >= s.capacity {
		return fmt.Errorf("%w: capacity %d", ErrRevocationStoreFull, s.capacity)
	}

	s.generation++
	entry := revocationEntry{reason: reason, expiresAt: expiresAt, generation: s.generation}
	s.items[id] = entry
	if !expiresAt.IsZero() {
		heap.Push(&s.expirations, revocationExpiry{id: id, expiresAt: expiresAt, generation: entry.generation})
	}

	s.compactExpirationsLocked()

	return nil
}

func (s *memoryRevocationStore) IsRevoked(_ context.Context, id string) (bool, error) {
	if id == "" {
		return false, ErrInvalidRevocationID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.removeExpiredLocked(s.now())
	_, ok := s.items[id]

	return ok, nil
}

func (s *memoryRevocationStore) removeExpiredLocked(now time.Time) {
	for len(s.expirations) > 0 && !s.expirations[0].expiresAt.After(now) {
		expired := heap.Pop(&s.expirations).(revocationExpiry)
		entry, ok := s.items[expired.id]
		if ok && entry.generation == expired.generation && !entry.live(now) {
			delete(s.items, expired.id)
		}
	}
}

// compactExpirationsLocked bounds stale heap nodes caused by repeatedly
// replacing the same ID. The occasional O(n) rebuild is amortized across at
// least O(n) updates; no Revoke performs an unconditional map sweep.
func (s *memoryRevocationStore) compactExpirationsLocked() {
	if len(s.expirations) <= 2*len(s.items)+64 {
		return
	}

	rebuilt := make(revocationExpiryHeap, 0, len(s.items))
	for id, entry := range s.items {
		if !entry.expiresAt.IsZero() {
			rebuilt = append(rebuilt, revocationExpiry{id: id, expiresAt: entry.expiresAt, generation: entry.generation})
		}
	}

	heap.Init(&rebuilt)
	s.expirations = rebuilt
}
