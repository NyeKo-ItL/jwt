package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxJWKSBytes   = 1 << 20 // 1 MiB
	defaultMinRefresh     = time.Minute
	defaultFetcherTimeout = 30 * time.Second
	wellKnownOpenIDConfig = "/.well-known/openid-configuration"
	wellKnownJWKSFallback = "/.well-known/jwks.json"
)

// KeyFetcher retrieves and caches a remote JWKS document; it satisfies
// KeyProvider directly, so it plugs in wherever a KeySet would. HTTPS-only,
// size-capped, and it honours a Cache-Control: max-age hint when present.
type KeyFetcher struct {
	uri        string
	client     *http.Client
	minRefresh time.Duration
	maxBytes   int64

	mu        sync.Mutex
	set       *KeySet
	fetchedAt time.Time
	freshFor  time.Duration // from Cache-Control: max-age, 0 if absent
	now       func() time.Time
}

// FetcherOption configures a KeyFetcher.
type FetcherOption func(*KeyFetcher)

// WithHTTPClient sets the HTTP client used for JWKS and discovery requests.
func WithHTTPClient(c *http.Client) FetcherOption {
	return func(f *KeyFetcher) {
		if c != nil {
			f.client = c
		}
	}
}

// WithMinRefreshInterval sets the shortest interval between network fetches
// triggered by a cache miss (default 1 minute). Refresh bypasses it.
func WithMinRefreshInterval(d time.Duration) FetcherOption {
	return func(f *KeyFetcher) {
		if d > 0 {
			f.minRefresh = d
		}
	}
}

// WithMaxResponseBytes caps the JWKS response body size (default 1 MiB).
func WithMaxResponseBytes(n int64) FetcherOption {
	return func(f *KeyFetcher) {
		if n > 0 {
			f.maxBytes = n
		}
	}
}

// NewKeyFetcher returns a KeyFetcher for the given JWKS URI.
func NewKeyFetcher(uri string, opts ...FetcherOption) *KeyFetcher {
	f := &KeyFetcher{
		uri:        uri,
		client:     &http.Client{Timeout: defaultFetcherTimeout},
		minRefresh: defaultMinRefresh,
		maxBytes:   defaultMaxJWKSBytes,
		now:        time.Now,
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

// Lookup resolves a key by kid, fetching (or refetching, subject to the
// caching rules) the JWKS document as needed. It satisfies KeyProvider.
func (f *KeyFetcher) Lookup(ctx context.Context, kid string) (Key, bool, error) {
	f.mu.Lock()
	set := f.set
	stale := set == nil || f.stale()
	mayRefresh := f.canRefresh()
	f.mu.Unlock()

	if !stale {
		if k, ok, _ := set.Lookup(ctx, kid); ok {
			return k, true, nil
		}
		// Cache miss against a still-fresh document: refetch once (a new
		// signing key may have been published), but not more often than
		// minRefresh.
		if !mayRefresh {
			return Key{}, false, nil
		}
	}

	if err := f.Refresh(ctx); err != nil {
		return Key{}, false, err
	}
	f.mu.Lock()
	set = f.set
	f.mu.Unlock()
	return set.Lookup(ctx, kid)
}

// stale reports whether the cached document has aged past its freshness
// window (Cache-Control max-age, or minRefresh when no hint was given).
func (f *KeyFetcher) stale() bool {
	window := f.freshFor
	if window <= 0 {
		window = f.minRefresh
	}
	return f.now().Sub(f.fetchedAt) >= window
}

func (f *KeyFetcher) canRefresh() bool {
	return f.now().Sub(f.fetchedAt) >= f.minRefresh
}

// Refresh forces an immediate re-fetch of the JWKS document.
func (f *KeyFetcher) Refresh(ctx context.Context) error {
	set, maxAge, err := fetchJWKS(ctx, f.client, f.uri, f.maxBytes)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.set = set
	f.fetchedAt = f.now()
	f.freshFor = maxAge
	f.mu.Unlock()
	return nil
}

func fetchJWKS(ctx context.Context, client *http.Client, uri string, maxBytes int64) (*KeySet, time.Duration, error) {
	if err := requireHTTPS(uri); err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("jwt: fetching JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("jwt: fetching JWKS: unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("jwt: reading JWKS: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, 0, fmt.Errorf("%w: JWKS document exceeds %d bytes", ErrMalformedKey, maxBytes)
	}
	set, err := ParseKeySet(body)
	if err != nil {
		return nil, 0, err
	}
	return set, parseMaxAge(resp.Header.Get("Cache-Control")), nil
}

func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: JWKS URI must be https, got %q", ErrMalformedKey, u.Scheme)
	}
	return nil
}

// parseMaxAge extracts the max-age value (seconds) from a Cache-Control
// header, returning 0 when absent or non-positive.
func parseMaxAge(header string) time.Duration {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		v, ok := strings.CutPrefix(part, "max-age=")
		if !ok {
			continue
		}
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

// DiscoverJWKSURI resolves a JWKS URI from an issuer's OIDC/OAuth discovery
// document (<issuer>/.well-known/openid-configuration). If that document
// cannot be fetched or lacks "jwks_uri", it falls back to the conventional
// <issuer>/.well-known/jwks.json. A nil client uses http.DefaultClient.
func DiscoverJWKSURI(ctx context.Context, issuer string, client *http.Client) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	base := strings.TrimRight(issuer, "/")
	if base == "" {
		return "", fmt.Errorf("%w: empty issuer", ErrMalformedKey)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+wellKnownOpenIDConfig, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var doc struct {
				JWKSURI string `json:"jwks_uri"`
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, defaultMaxJWKSBytes))
			if json.Unmarshal(body, &doc) == nil && doc.JWKSURI != "" {
				return doc.JWKSURI, nil
			}
		}
	}
	return base + wellKnownJWKSFallback, nil
}
