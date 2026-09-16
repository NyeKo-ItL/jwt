package jwt

import (
	"context"
	"errors"
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
	defaultMaxJWKSBytes     = 1 << 20 // 1 MiB
	defaultMinRefresh       = time.Minute
	defaultFetcherTimeout   = 30 * time.Second
	defaultMaxCacheDuration = 24 * time.Hour
	maxRedirects            = 10
	wellKnownOpenIDConfig   = "/.well-known/openid-configuration"
)

// ErrKeyFetch reports that remote key material could not be obtained: a
// network or TLS failure, a non-200 response, an oversized or malformed
// document, a redirect away from HTTPS, or an OIDC discovery document that
// fails validation. It signals an infrastructure problem, not a bad token.
var ErrKeyFetch = errors.New("jwt: fetching remote keys failed")

// KeyFetcher retrieves and caches a remote JWKS document (RFC 7517 §5); it
// satisfies KeyProvider directly, so it plugs in wherever a KeySet would.
//
// Hardening, all on by default:
//   - HTTPS only, including every redirect hop (a redirect to any other
//     scheme fails with ErrKeyFetch).
//   - The response body is size-capped (WithMaxResponseBytes).
//   - Concurrent lookups share a single in-flight request, and network
//     attempts — successful or not — are rate-limited to one per
//     WithMinRefreshInterval, so unknown "kid" values or an unreachable
//     upstream cannot amplify traffic.
//   - A Cache-Control max-age hint is honored but capped
//     (WithMaxCacheDuration), so a revoked key cannot stay pinned for long.
//   - When a refresh fails, keys from the last good document keep resolving.
type KeyFetcher struct {
	uri        string
	client     *http.Client
	minRefresh time.Duration
	maxBytes   int64
	maxCache   time.Duration

	mu          sync.Mutex
	set         *KeySet
	fetchedAt   time.Time
	freshFor    time.Duration // from Cache-Control: max-age (capped), 0 if absent
	lastAttempt time.Time     // start of the most recent network attempt
	lastErr     error         // outcome of the most recent completed attempt
	inflight    *fetchFlight
	now         func() time.Time
}

// fetchFlight is one in-progress network fetch that concurrent callers join.
type fetchFlight struct {
	done chan struct{}
	err  error
}

// FetcherOption configures a KeyFetcher.
type FetcherOption func(*KeyFetcher)

// WithHTTPClient sets the HTTP client used for JWKS requests. The client is
// copied, never modified: the copy wraps its CheckRedirect so that no
// redirect may leave HTTPS, then defers to the caller's own policy.
func WithHTTPClient(c *http.Client) FetcherOption {
	return func(f *KeyFetcher) {
		if c != nil {
			f.client = c
		}
	}
}

// WithMinRefreshInterval sets the shortest interval between network attempts
// triggered by Lookup (default 1 minute). It also acts as the retry backoff
// after a failed attempt. Refresh bypasses it.
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

// WithMaxCacheDuration caps how long a Cache-Control max-age hint may keep a
// document fresh (default 24 hours). Non-positive values are ignored.
func WithMaxCacheDuration(d time.Duration) FetcherOption {
	return func(f *KeyFetcher) {
		if d > 0 {
			f.maxCache = d
		}
	}
}

// NewKeyFetcher returns a KeyFetcher for the given JWKS URI. Nothing is
// fetched until the first Lookup or Refresh.
func NewKeyFetcher(uri string, opts ...FetcherOption) *KeyFetcher {
	f := &KeyFetcher{
		uri:        uri,
		minRefresh: defaultMinRefresh,
		maxBytes:   defaultMaxJWKSBytes,
		maxCache:   defaultMaxCacheDuration,
		now:        time.Now,
	}
	for _, o := range opts {
		o(f)
	}

	f.client = safeHTTPClient(f.client)

	return f
}

// Lookup resolves a key by kid, fetching (or refetching, subject to the
// caching and rate-limiting rules) the JWKS document as needed. It satisfies
// KeyProvider. A kid absent from a successfully fetched document is reported
// as not found with a nil error; a fetch failure is reported as ErrKeyFetch
// unless the last good document still holds the key.
func (f *KeyFetcher) Lookup(ctx context.Context, kid string) (Key, bool, error) {
	f.mu.Lock()
	now := f.now()

	if f.set != nil {
		if k, ok := f.set.lookup(kid); ok && !f.staleAt(now) {
			f.mu.Unlock()
			return k, true, nil
		}
	}

	if f.inflight == nil && !f.mayAttemptAt(now) {
		// Rate-limited: answer from whatever is cached, stale or not.
		set, lastErr := f.set, f.lastErr
		f.mu.Unlock()

		return lookupOrErr(set, kid, lastErr)
	}

	fl := f.startFlightLocked(ctx, now)
	f.mu.Unlock()

	if err := waitFlight(ctx, fl); err != nil {
		return Key{}, false, err
	}

	f.mu.Lock()
	set := f.set
	f.mu.Unlock()

	return lookupOrErr(set, kid, fl.err)
}

// lookupOrErr answers from set when it holds kid (serving stale keys through
// an outage), otherwise reports err (nil meaning a clean "not found").
func lookupOrErr(set *KeySet, kid string, err error) (Key, bool, error) {
	if set != nil {
		if k, ok := set.lookup(kid); ok {
			return k, true, nil
		}
	}

	return Key{}, false, err
}

// staleAt reports whether the cached document has aged past its freshness
// window (the capped Cache-Control max-age, or minRefresh when no hint was
// given).
func (f *KeyFetcher) staleAt(now time.Time) bool {
	window := f.freshFor
	if window <= 0 {
		window = f.minRefresh
	}

	return now.Sub(f.fetchedAt) >= window
}

// mayAttemptAt reports whether the rate limit allows a new network attempt.
func (f *KeyFetcher) mayAttemptAt(now time.Time) bool {
	return f.lastAttempt.IsZero() || now.Sub(f.lastAttempt) >= f.minRefresh
}

// Refresh forces an immediate re-fetch of the JWKS document, ignoring the
// rate limit. If a fetch is already in flight, Refresh joins it instead of
// starting another.
func (f *KeyFetcher) Refresh(ctx context.Context) error {
	f.mu.Lock()
	fl := f.startFlightLocked(ctx, f.now())
	f.mu.Unlock()

	if err := waitFlight(ctx, fl); err != nil {
		return err
	}

	return fl.err
}

// startFlightLocked joins the in-flight fetch or starts a new one. The fetch
// runs detached from the caller's cancellation so one impatient caller cannot
// fail everyone who joined; it stays bounded by the HTTP client timeout (or
// defaultFetcherTimeout when the client has none). f.mu must be held.
func (f *KeyFetcher) startFlightLocked(ctx context.Context, now time.Time) *fetchFlight {
	if f.inflight != nil {
		return f.inflight
	}

	fl := &fetchFlight{done: make(chan struct{})}
	f.inflight = fl
	f.lastAttempt = now

	fetchCtx := context.WithoutCancel(ctx)

	cancel := context.CancelFunc(func() {})
	if f.client.Timeout <= 0 {
		fetchCtx, cancel = context.WithTimeout(fetchCtx, defaultFetcherTimeout)
	}

	go func() {
		defer cancel()

		set, maxAge, err := fetchJWKS(fetchCtx, f.client, f.uri, f.maxBytes)

		f.mu.Lock()
		if err == nil {
			f.set = set
			f.fetchedAt = f.now()
			f.freshFor = min(maxAge, f.maxCache)
		}

		f.lastErr = err
		fl.err = err
		f.inflight = nil
		f.mu.Unlock()

		close(fl.done)
	}()

	return fl
}

// waitFlight blocks until fl completes or ctx ends, returning ctx's error in
// the latter case.
func waitFlight(ctx context.Context, fl *fetchFlight) error {
	select {
	case <-fl.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// safeHTTPClient returns a copy of c (or a default client with a timeout when
// c is nil) whose redirect policy refuses any hop that is not HTTPS before
// deferring to c's own CheckRedirect, or to a 10-hop limit when c has none.
func safeHTTPClient(c *http.Client) *http.Client {
	var out http.Client
	if c == nil {
		out.Timeout = defaultFetcherTimeout
	} else {
		out = *c
	}

	next := out.CheckRedirect
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("%w: refusing redirect to non-https URL %q", ErrKeyFetch, req.URL.Redacted())
		}

		if next != nil {
			return next(req, via)
		}

		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: stopped after %d redirects", ErrKeyFetch, maxRedirects)
		}

		return nil
	}

	return &out
}

// getCapped performs a GET for uri (HTTPS enforced) and returns a body of at
// most maxBytes, plus the response headers. Every failure wraps ErrKeyFetch.
func getCapped(ctx context.Context, client *http.Client, uri, accept string, maxBytes int64) ([]byte, http.Header, error) {
	if err := requireHTTPS(uri); err != nil {
		return nil, nil, err
	}

	//nolint:gosec // The URL is explicit caller configuration (or a validated discovery result); HTTPS is enforced above and on every redirect.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrKeyFetch, err)
	}

	req.Header.Set("Accept", accept)
	//nolint:gosec // The URL is explicit caller configuration; HTTPS is enforced above and on every redirect.
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrKeyFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%w: unexpected status %s", ErrKeyFetch, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: reading body: %w", ErrKeyFetch, err)
	}

	if int64(len(body)) > maxBytes {
		return nil, nil, fmt.Errorf("%w: document exceeds %d bytes", ErrKeyFetch, maxBytes)
	}

	return body, resp.Header, nil
}

func fetchJWKS(ctx context.Context, client *http.Client, uri string, maxBytes int64) (*KeySet, time.Duration, error) {
	body, header, err := getCapped(ctx, client, uri, "application/jwk-set+json, application/json", maxBytes)
	if err != nil {
		return nil, 0, err
	}

	set, err := ParseKeySet(body)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrKeyFetch, err)
	}

	return set, parseMaxAge(header.Get("Cache-Control")), nil
}

// requireHTTPS rejects anything but an absolute https URL with a host.
func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %w: %w", ErrKeyFetch, ErrMalformedKey, err)
	}

	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: %w: URL must be absolute https, got %q", ErrKeyFetch, ErrMalformedKey, u.Redacted())
	}

	return nil
}

// parseMaxAge extracts the max-age value (seconds) from a Cache-Control
// header, returning 0 when absent or non-positive.
func parseMaxAge(header string) time.Duration {
	for part := range strings.SplitSeq(header, ",") {
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

// DiscoverJWKSURI resolves the "jwks_uri" of an OpenID Provider from its
// discovery document, as specified by OpenID Connect Discovery 1.0:
//
//   - issuer must be an https URL with no query or fragment (OIDC Core §2);
//   - the document is fetched from issuer, minus any terminating "/", plus
//     "/.well-known/openid-configuration" (Discovery §4);
//   - the document's "issuer" MUST be identical to the issuer requested
//     (Discovery §4.3), which defeats mix-up and substituted documents;
//   - "jwks_uri" must be present and https.
//
// Every failure — network, status, size, JSON, or validation — wraps
// ErrKeyFetch; there is no silent fallback to a guessed URL. A nil client
// uses a default client with a 30-second timeout; a supplied client is copied
// and given the same HTTPS-only redirect guard as KeyFetcher.
func DiscoverJWKSURI(ctx context.Context, issuer string, client *http.Client) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%w: issuer must be an https URL without query or fragment, got %q", ErrKeyFetch, issuer)
	}

	body, _, err := getCapped(ctx, safeHTTPClient(client),
		strings.TrimSuffix(issuer, "/")+wellKnownOpenIDConfig, "application/json", defaultMaxJWKSBytes)
	if err != nil {
		return "", err
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := decodeObject(body, &doc); err != nil {
		return "", fmt.Errorf("%w: discovery document: %w", ErrKeyFetch, err)
	}

	if doc.Issuer != issuer {
		return "", fmt.Errorf("%w: discovery document issuer %q does not match %q", ErrKeyFetch, doc.Issuer, issuer)
	}

	if doc.JWKSURI == "" {
		return "", fmt.Errorf("%w: discovery document has no jwks_uri", ErrKeyFetch)
	}

	if err := requireHTTPS(doc.JWKSURI); err != nil {
		return "", err
	}

	return doc.JWKSURI, nil
}
