package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// KeySet is a mutable, concurrency-safe KeyProvider (RFC 7517 §5's JWK Set) —
// the library's built-in in-memory implementation. Insertion order is
// preserved for serving as a JWKS document.
type KeySet struct {
	mu   sync.RWMutex
	keys []Key
}

// NewKeySet returns a KeySet seeded with keys.
func NewKeySet(keys ...Key) *KeySet {
	s := &KeySet{}
	for _, k := range keys {
		s.Add(k)
	}
	return s
}

// Add inserts k, replacing any existing key with the same non-empty kid.
func (s *KeySet) Add(k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k.Kid != "" {
		for i := range s.keys {
			if s.keys[i].Kid == k.Kid {
				s.keys[i] = k
				return
			}
		}
	}
	s.keys = append(s.keys, k)
}

// Remove deletes every key with the given kid.
func (s *KeySet) Remove(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.keys[:0]
	for _, k := range s.keys {
		if k.Kid != kid {
			out = append(out, k)
		}
	}
	s.keys = out
}

// Lookup resolves a key by kid. An empty kid matches a sole key (or a sole
// key that itself has no kid); it is ambiguous when the set holds several
// keys, and Lookup then reports not-found rather than guessing.
func (s *KeySet) Lookup(_ context.Context, kid string) (Key, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if kid == "" {
		if len(s.keys) == 1 {
			return s.keys[0], true, nil
		}
		return Key{}, false, nil
	}
	for _, k := range s.keys {
		if k.Kid == kid {
			return k, true, nil
		}
	}
	return Key{}, false, nil
}

// Keys returns a snapshot copy of the set, for serving as a JWKS document.
func (s *KeySet) Keys(_ context.Context) ([]Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Key(nil), s.keys...), nil
}

// MarshalJSON renders the set as an RFC 7517 §5 JWK Set document. It fails if
// any contained key refuses to marshal (e.g. a symmetric "oct" key, which
// must never be published — see Key.MarshalJSON).
func (s *KeySet) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(struct {
		Keys []Key `json:"keys"`
	}{Keys: s.keys})
}

// ParseKeySet parses a JWKS document ({"keys":[ ... ]}) into a ready-to-use
// KeySet. Unlike many hand-rolled parsers it does not silently drop keys it
// cannot fully interpret: a malformed member is an error.
func ParseKeySet(data []byte) (*KeySet, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: JWKS document: %v", ErrMalformedKey, err)
	}
	if doc.Keys == nil {
		return nil, fmt.Errorf("%w: JWKS document has no \"keys\" array", ErrMalformedKey)
	}
	s := &KeySet{}
	for i, raw := range doc.Keys {
		k, err := ParseKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: JWKS key #%d: %v", ErrMalformedKey, i, err)
		}
		s.Add(k)
	}
	return s, nil
}
