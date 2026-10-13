package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Defensive limits for untrusted JWKS documents. They permit 8192-bit RSA
// moduli and unusually large symmetric keys while bounding parser allocation.
const (
	MaxKeySetKeys         = 128
	MaxJWKJSONBytes       = 64 << 10
	MaxJWKMaterialBytes   = 8 << 10
	MaxKeySetJSONBytes    = MaxKeySetKeys*MaxJWKJSONBytes + 1024
	maxJWKMaterialEncoded = (MaxJWKMaterialBytes*8 + 5) / 6
)

// KeySet is a mutable, concurrency-safe KeyProvider (RFC 7517 §5's JWK Set) —
// the library's built-in in-memory implementation. Insertion order is
// preserved for serving as a JWKS document. Keys are deep-copied at every
// boundary, so callers cannot mutate material held by the set.
type KeySet struct {
	mu    sync.RWMutex
	keys  []Key
	byKID map[string]int
}

// NewKeySet returns a KeySet seeded with deep copies of keys.
func NewKeySet(keys ...Key) *KeySet {
	s := &KeySet{byKID: make(map[string]int, len(keys))}
	for _, k := range keys {
		s.Add(k)
	}

	return s
}

// Clone returns an independent deep copy of s.
func (s *KeySet) Clone() *KeySet {
	if s == nil {
		return NewKeySet()
	}

	keys, _ := s.Keys(context.Background())

	return NewKeySet(keys...)
}

// Add inserts a deep copy of k, replacing any existing key with the same
// non-empty kid while retaining its insertion-order position.
func (s *KeySet) Add(k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.byKID == nil {
		s.byKID = make(map[string]int)
	}

	clone := k.Clone()
	if clone.Kid != "" {
		if i, ok := s.byKID[clone.Kid]; ok {
			s.keys[i] = clone
			return
		}
	}

	s.keys = append(s.keys, clone)
	if clone.Kid != "" {
		s.byKID[clone.Kid] = len(s.keys) - 1
	}
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

	clear(s.keys[len(out):])
	s.keys = out
	s.rebuildIndexLocked()
}

func (s *KeySet) rebuildIndexLocked() {
	s.byKID = make(map[string]int, len(s.keys))
	for i := range s.keys {
		if s.keys[i].Kid != "" {
			s.byKID[s.keys[i].Kid] = i
		}
	}
}

// Lookup resolves a key by kid. An empty kid matches a sole key (or a sole
// key that itself has no kid); it is ambiguous when the set holds several
// keys, and Lookup then reports not-found rather than guessing. Returned keys
// are deep copies.
func (s *KeySet) Lookup(_ context.Context, kid string) (Key, bool, error) {
	k, ok := s.lookup(kid)

	return k, ok, nil
}

func (s *KeySet) lookup(kid string) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if kid == "" {
		if len(s.keys) == 1 {
			return s.keys[0].Clone(), true
		}

		return Key{}, false
	}

	i, ok := s.byKID[kid]
	if !ok || i < 0 || i >= len(s.keys) {
		return Key{}, false
	}

	return s.keys[i].Clone(), true
}

// Keys returns a deep snapshot copy of the set, for serving as a JWKS
// document.
func (s *KeySet) Keys(_ context.Context) ([]Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]Key, len(s.keys))
	for i := range s.keys {
		keys[i] = s.keys[i].Clone()
	}

	return keys, nil
}

// MarshalJSON renders the set as an RFC 7517 §5 JWK Set document. It fails if
// any contained key refuses to marshal (e.g. a symmetric "oct" key, which
// must never be published — see Key.MarshalJSON).
func (s *KeySet) MarshalJSON() ([]byte, error) {
	keys, _ := s.Keys(context.Background())

	return json.Marshal(struct {
		Keys []Key `json:"keys"`
	}{Keys: keys})
}

// KeySetDiagnostic describes a key ignored by ParseKeySetPermissive.
type KeySetDiagnostic struct {
	Index int
	Err   error
}

func (d KeySetDiagnostic) Error() string {
	return fmt.Sprintf("JWKS key #%d: %v", d.Index, d.Err)
}

// Unwrap exposes the malformed-key cause for errors.Is/errors.As.
func (d KeySetDiagnostic) Unwrap() error { return d.Err }

// ParseKeySet parses a JWKS document ({"keys":[ ... ]}) in strict mode. A
// malformed or unsupported member rejects the complete set. The document,
// member count, member JSON size, and encoded key-material sizes are bounded by
// the exported Max* constants above.
func ParseKeySet(data []byte) (*KeySet, error) {
	s, _, err := parseKeySet(data, false)

	return s, err
}

// ParseKeySetPermissive parses an RFC 7517 §5 JWK Set while ignoring members
// whose key type or representation is not understood. Each ignored member is
// reported in diagnostics. Document-level syntax and all resource limits stay
// fatal; valid understood keys are returned in their original order.
func ParseKeySetPermissive(data []byte) (*KeySet, []KeySetDiagnostic, error) {
	return parseKeySet(data, true)
}

func parseKeySet(data []byte, permissive bool) (*KeySet, []KeySetDiagnostic, error) {
	if len(data) > MaxKeySetJSONBytes {
		return nil, nil, fmt.Errorf("%w: JWKS document exceeds %d bytes", ErrMalformedKey, MaxKeySetJSONBytes)
	}

	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := decodeObject(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: JWKS document: %w", ErrMalformedKey, err)
	}

	if doc.Keys == nil {
		return nil, nil, fmt.Errorf("%w: JWKS document has no \"keys\" array", ErrMalformedKey)
	}

	if len(doc.Keys) > MaxKeySetKeys {
		return nil, nil, fmt.Errorf("%w: JWKS has %d keys, limit is %d", ErrMalformedKey, len(doc.Keys), MaxKeySetKeys)
	}

	s := NewKeySet()
	diagnostics := make([]KeySetDiagnostic, 0)

	for i, raw := range doc.Keys {
		k, err := parseBoundedJWK(raw)
		if err != nil {
			wrapped := fmt.Errorf("%w: JWKS key #%d: %w", ErrMalformedKey, i, err)
			if !permissive {
				return nil, nil, wrapped
			}

			diagnostics = append(diagnostics, KeySetDiagnostic{Index: i, Err: wrapped})
			continue
		}

		if permissive && !understandsJWK(k) {
			diagnostics = append(diagnostics, KeySetDiagnostic{
				Index: i,
				Err:   fmt.Errorf("%w: unsupported JWK kty %q or curve %q", ErrUnsupportedAlgorithm, k.Kty, k.crv),
			})
			continue
		}

		s.Add(k)
	}

	return s, diagnostics, nil
}

func understandsJWK(k Key) bool {
	switch k.Kty {
	case KeyTypeRSA, KeyTypeOct:
		return true
	case KeyTypeEC:
		return curveByName(k.crv) != nil
	case KeyTypeOKP:
		return k.crv == "Ed25519"
	default:
		return false
	}
}

func parseBoundedJWK(raw []byte) (Key, error) {
	if len(raw) > MaxJWKJSONBytes {
		return Key{}, fmt.Errorf("%w: JWK exceeds %d JSON bytes", ErrMalformedKey, MaxJWKJSONBytes)
	}

	var material struct {
		N string `json:"n"`
		E string `json:"e"`
		X string `json:"x"`
		Y string `json:"y"`
		K string `json:"k"`
	}
	if err := decodeObject(raw, &material); err != nil {
		return Key{}, fmt.Errorf("%w: invalid JWK object: %w", ErrMalformedKey, err)
	}

	for name, encoded := range map[string]string{
		"n": material.N,
		"e": material.E,
		"x": material.X,
		"y": material.Y,
		"k": material.K,
	} {
		if len(encoded) > maxJWKMaterialEncoded {
			return Key{}, fmt.Errorf("%w: JWK member %q exceeds %d decoded bytes", ErrMalformedKey, name, MaxJWKMaterialBytes)
		}
	}

	return ParseKey(raw)
}
