package jwt

import (
	"context"
	"errors"
)

// KeyProvider resolves a Key by "kid" (which may be empty, meaning "the only
// key"). Parse uses it to obtain the verification key for a token. A single
// fixed key and a full JWKS-backed store satisfy the same interface.
type KeyProvider interface {
	// Lookup returns the key for kid. The bool is false (with a nil error)
	// when no such key exists; a non-nil error signals a backing-store
	// failure and aborts Parse. Parse wraps such errors with ErrKeyProvider
	// while preserving the original error for errors.Is/errors.As.
	Lookup(ctx context.Context, kid string) (key Key, found bool, err error)
}

// VerifierProvider resolves a caller-defined Verifier by the protected "alg"
// and "kid" header parameters. Use WithVerifierProvider to make Parse or
// Middleware use it instead of a KeyProvider. Parse still enforces its
// algorithm allowlist and checks that the returned Verifier reports the same
// algorithm and, when the token has a kid, the same key ID.
type VerifierProvider interface {
	// LookupVerifier returns a verifier for alg and kid. The bool is false (with
	// a nil error) when no verifier exists. Parse wraps callback errors with
	// ErrVerifierProvider while preserving the original error.
	LookupVerifier(ctx context.Context, alg Algorithm, kid string) (verifier Verifier, found bool, err error)
}

// VerifierProviderFunc adapts a function to VerifierProvider.
type VerifierProviderFunc func(context.Context, Algorithm, string) (Verifier, bool, error)

// LookupVerifier calls f. A nil VerifierProviderFunc is treated as an absent
// provider when passed through WithVerifierProvider.
func (f VerifierProviderFunc) LookupVerifier(ctx context.Context, alg Algorithm, kid string) (Verifier, bool, error) {
	return f(ctx, alg, kid)
}

// ErrKeyProvider marks an infrastructure error returned by KeyProvider.Lookup.
// The returned error also wraps the provider's original error.
var ErrKeyProvider = errors.New("jwt: KeyProvider lookup failed")

// ErrVerifierProvider marks an infrastructure error returned by
// VerifierProvider.LookupVerifier. The returned error also wraps the
// provider's original error.
var ErrVerifierProvider = errors.New("jwt: VerifierProvider lookup failed")

type staticKeyProvider struct{ key Key }

// StaticKeyProvider adapts a single fixed Key — the common case where an
// application has exactly one signing key. A non-empty requested kid that
// does not match the key's own non-empty kid resolves to "not found".
func StaticKeyProvider(k Key) KeyProvider {
	return staticKeyProvider{key: k.Clone()}
}

func (s staticKeyProvider) Lookup(_ context.Context, kid string) (Key, bool, error) {
	if kid != "" && s.key.Kid != "" && kid != s.key.Kid {
		return Key{}, false, nil
	}

	return s.key.Clone(), true, nil
}

type mapKeyProvider struct{ byKID map[string]Key }

// MapKeyProvider adapts a fixed set of Keys, keyed by kid. As with any
// KeyProvider, an empty requested kid resolves to the sole key when the map
// holds exactly one.
func MapKeyProvider(byKID map[string]Key) KeyProvider {
	m := make(map[string]Key, len(byKID))
	for kid, key := range byKID {
		m[kid] = key.Clone()
	}

	return mapKeyProvider{byKID: m}
}

func (m mapKeyProvider) Lookup(_ context.Context, kid string) (Key, bool, error) {
	if kid == "" && len(m.byKID) == 1 {
		for _, k := range m.byKID {
			return k.Clone(), true, nil
		}
	}

	k, ok := m.byKID[kid]

	return k.Clone(), ok, nil
}
