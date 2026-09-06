package jwt

import "maps"

import "context"

// KeyProvider resolves a Key by "kid" (which may be empty, meaning "the only
// key"). Parse uses it to obtain the verification key for a token. A single
// fixed key and a full JWKS-backed store satisfy the same interface.
type KeyProvider interface {
	Lookup(ctx context.Context, kid string) (Key, bool, error)
}

type staticKeyProvider struct{ key Key }

// StaticKeyProvider adapts a single fixed Key — the common case where an
// application has exactly one signing key. A non-empty requested kid that
// does not match the key's own non-empty kid resolves to "not found".
func StaticKeyProvider(k Key) KeyProvider {
	return staticKeyProvider{key: k}
}

func (s staticKeyProvider) Lookup(_ context.Context, kid string) (Key, bool, error) {
	if kid != "" && s.key.Kid != "" && kid != s.key.Kid {
		return Key{}, false, nil
	}
	return s.key, true, nil
}

type mapKeyProvider struct{ byKID map[string]Key }

// MapKeyProvider adapts a fixed set of Keys, keyed by kid.
func MapKeyProvider(byKID map[string]Key) KeyProvider {
	m := make(map[string]Key, len(byKID))
	maps.Copy(m, byKID)
	return mapKeyProvider{byKID: m}
}

func (m mapKeyProvider) Lookup(_ context.Context, kid string) (Key, bool, error) {
	k, ok := m.byKID[kid]
	return k, ok, nil
}
