package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxJWKSBytes     = 1 << 20 // 1 MiB
	defaultMaxKeyCount      = 100
	defaultMinRefresh       = time.Minute
	defaultFetcherTimeout   = 30 * time.Second
	defaultMaxCacheDuration = 24 * time.Hour
	defaultMaxStaleDuration = 24 * time.Hour
	maxRedirects            = 10
	wellKnownOpenIDConfig   = "/.well-known/openid-configuration"
	maxDuration             = time.Duration(1<<63 - 1)
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
//   - Cache-Control is honored and max-age is capped
//     (WithMaxCacheDuration), so a revoked key cannot stay pinned for long.
//   - Failed refreshes may use the last good document only for the bounded
//     WithMaxStaleDuration window; the default eventually fails closed.
//   - The default URL policy rejects local, private-looking, and IP-literal
//     targets. Callers must still preapprove issuer hostnames: no DNS lookup is
//     performed because checking an address without binding the HTTP dial to
//     that same address would introduce a DNS TOCTOU vulnerability.
type KeyFetcher struct {
	uri        string
	client     *http.Client
	urlPolicy  URLPolicy
	minRefresh time.Duration
	maxBytes   int64
	maxKeys    int
	maxCache   time.Duration
	maxStale   time.Duration

	mu          sync.Mutex
	set         *KeySet
	fetchedAt   time.Time
	freshFor    time.Duration
	lastAttempt time.Time // start of the most recent network attempt
	lastErr     error     // outcome of the most recent completed attempt
	inflight    *fetchFlight
	now         func() time.Time
}

// fetchFlight is one in-progress network fetch that concurrent callers join.
type fetchFlight struct {
	done chan struct{}
	set  *KeySet
	err  error
}

// URLPolicy validates an absolute HTTPS URL before a request is sent. It is
// applied to the initial URL, discovery results, and every redirect. Policies
// used by a KeyFetcher must be safe for concurrent use.
type URLPolicy func(*url.URL) error

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

// WithURLPolicy replaces the default URL/network policy. Use an allowlist
// policy when the URI or issuer originates from untrusted input. A nil policy
// is ignored. The policy does not replace HTTPS validation.
func WithURLPolicy(policy URLPolicy) FetcherOption {
	return func(f *KeyFetcher) {
		if policy != nil {
			f.urlPolicy = policy
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

// WithMaxKeyCount caps the number of keys accepted in one JWKS document
// (default 100). Non-positive values are ignored.
func WithMaxKeyCount(n int) FetcherOption {
	return func(f *KeyFetcher) {
		if n > 0 {
			f.maxKeys = n
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

// WithMaxStaleDuration sets how long a stale cached document may be used when
// refresh fails (default 24 hours). Zero disables stale serving. Negative
// values are ignored.
func WithMaxStaleDuration(d time.Duration) FetcherOption {
	return func(f *KeyFetcher) {
		if d >= 0 {
			f.maxStale = d
		}
	}
}

// NewKeyFetcher returns a KeyFetcher for the given JWKS URI. Nothing is
// fetched until the first Lookup or Refresh. The URI's issuer/host must be
// preapproved by the application even when the default URL policy is used.
func NewKeyFetcher(uri string, opts ...FetcherOption) *KeyFetcher {
	f := &KeyFetcher{
		uri:        uri,
		urlPolicy:  defaultURLPolicy,
		minRefresh: defaultMinRefresh,
		maxBytes:   defaultMaxJWKSBytes,
		maxKeys:    defaultMaxKeyCount,
		maxCache:   defaultMaxCacheDuration,
		maxStale:   defaultMaxStaleDuration,
		now:        time.Now,
	}

	for _, o := range opts {
		if o != nil {
			o(f)
		}
	}

	f.client = safeHTTPClient(f.client, f.urlPolicy)

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
		// Rate-limited: stale fallback remains bounded by maxStale.
		set, lastErr := f.fallbackLocked(now, f.lastErr)
		f.mu.Unlock()

		return lookupOrErr(set, kid, lastErr)
	}

	fl := f.startFlightLocked(ctx, now)
	f.mu.Unlock()

	if err := waitFlight(ctx, fl); err != nil {
		return Key{}, false, err
	}

	if fl.err == nil {
		// fl.set is also used for no-store responses: the callers that joined this
		// request may consume it, but it is not retained by the fetcher.
		return lookupOrErr(fl.set, kid, nil)
	}

	f.mu.Lock()
	set, err := f.fallbackLocked(f.now(), fl.err)
	f.mu.Unlock()

	return lookupOrErr(set, kid, err)
}

// lookupOrErr answers from set when it holds kid, otherwise reports err (nil
// meaning a clean "not found").
func lookupOrErr(set *KeySet, kid string, err error) (Key, bool, error) {
	if set != nil {
		if k, ok := set.lookup(kid); ok {
			return k, true, nil
		}
	}

	return Key{}, false, err
}

// staleAt reports whether the cached document has aged past its freshness
// window. freshFor is zero for no-cache and max-age=0 responses.
func (f *KeyFetcher) staleAt(now time.Time) bool {
	return cacheAge(now, f.fetchedAt) >= f.freshFor
}

// fallbackLocked returns the retained set only while its bounded stale window
// remains open. f.mu must be held.
func (f *KeyFetcher) fallbackLocked(now time.Time, fetchErr error) (*KeySet, error) {
	if f.set == nil {
		return nil, fetchErr
	}

	age := cacheAge(now, f.fetchedAt)
	if age < f.freshFor || age-f.freshFor < f.maxStale {
		return f.set, fetchErr
	}

	if fetchErr == nil {
		fetchErr = fmt.Errorf("%w: cached JWKS exceeded the maximum stale duration", ErrKeyFetch)
	}

	return nil, fetchErr
}

func cacheAge(now, fetchedAt time.Time) time.Duration {
	age := now.Sub(fetchedAt)
	if age < 0 {
		return 0
	}

	return age
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

		set, cache, err := fetchJWKS(fetchCtx, f.client, f.uri, f.maxBytes, f.maxKeys, f.urlPolicy)

		f.mu.Lock()
		fl.set = set

		if err == nil {
			if cache.noStore {
				f.set = nil
				f.fetchedAt = time.Time{}
				f.freshFor = 0
			} else {
				f.set = set
				f.fetchedAt = f.now()

				f.freshFor = f.minRefresh
				if cache.hasMaxAge {
					f.freshFor = min(cache.maxAge, f.maxCache)
				}

				if cache.noCache {
					f.freshFor = 0
				}
			}
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
// c is nil). Its redirect policy enforces HTTPS and URLPolicy before deferring
// to the caller's policy, or to a 10-hop limit when the caller has none.
func safeHTTPClient(c *http.Client, policies ...URLPolicy) *http.Client {
	var out http.Client
	if c == nil {
		out.Timeout = defaultFetcherTimeout
	} else {
		out = *c
	}

	policy := selectURLPolicy(policies)
	next := out.CheckRedirect
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := validateURL(req.URL, policy); err != nil {
			return err
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

// getCapped performs a GET for uri and returns a body of at most maxBytes,
// plus the response headers. HTTPS and URLPolicy are enforced before dialing;
// every failure wraps ErrKeyFetch.
func getCapped(ctx context.Context, client *http.Client, uri, accept string, maxBytes int64, policies ...URLPolicy) ([]byte, http.Header, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w: %w", ErrKeyFetch, ErrMalformedKey, err)
	}

	if err := validateURL(u, selectURLPolicy(policies)); err != nil {
		return nil, nil, err
	}

	//nolint:gosec // HTTPS and the configured URL policy are enforced above and on every redirect.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrKeyFetch, err)
	}

	req.Header.Set("Accept", accept)
	//nolint:gosec // HTTPS and the configured URL policy are enforced above and on every redirect.
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

type cacheControl struct {
	maxAge    time.Duration
	hasMaxAge bool
	noCache   bool
	noStore   bool
}

func fetchJWKS(ctx context.Context, client *http.Client, uri string, maxBytes int64, maxKeys int, policy URLPolicy) (*KeySet, cacheControl, error) {
	body, header, err := getCapped(ctx, client, uri, "application/jwk-set+json, application/json", maxBytes, policy)
	if err != nil {
		return nil, cacheControl{}, err
	}

	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err == nil && len(doc.Keys) > maxKeys {
		return nil, cacheControl{}, fmt.Errorf("%w: JWKS document has %d keys, limit is %d", ErrKeyFetch, len(doc.Keys), maxKeys)
	}

	set, err := ParseKeySet(body)
	if err != nil {
		return nil, cacheControl{}, fmt.Errorf("%w: %w", ErrKeyFetch, err)
	}

	return set, parseCacheControl(header.Values("Cache-Control")), nil
}

func validateHTTPSURL(u *url.URL) error {
	if u == nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		redacted := "<nil>"
		if u != nil {
			redacted = u.Redacted()
		}

		return fmt.Errorf("%w: %w: URL must be absolute https, got %q", ErrKeyFetch, ErrMalformedKey, redacted)
	}

	return nil
}

func validateURL(u *url.URL, policy URLPolicy) error {
	if err := validateHTTPSURL(u); err != nil {
		return err
	}

	if policy == nil {
		policy = defaultURLPolicy
	}

	if err := policy(u); err != nil {
		return fmt.Errorf("%w: URL policy rejected %q: %w", ErrKeyFetch, u.Redacted(), err)
	}

	return nil
}

func selectURLPolicy(policies []URLPolicy) URLPolicy {
	for _, policy := range policies {
		if policy != nil {
			return policy
		}
	}

	return defaultURLPolicy
}

// defaultURLPolicy rejects direct local/private targets without resolving DNS.
// Applications must additionally preapprove hostnames and, where DNS rebinding
// is in scope, supply a transport that binds validation and dialing together.
func defaultURLPolicy(u *url.URL) error {
	if u.User != nil {
		return errors.New("userinfo is not allowed")
	}

	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return errors.New("host is empty")
	}

	if ip := net.ParseIP(strings.TrimSuffix(host, "%")); ip != nil || strings.Contains(host, "%") {
		return errors.New("IP-literal hosts are not allowed")
	}

	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".home.arpa") || !strings.Contains(host, ".") {
		return errors.New("local or private-looking host is not allowed")
	}

	return nil
}

// parseMaxAge preserves the original helper contract for callers and tests.
func parseMaxAge(header string) time.Duration {
	cache := parseCacheControl([]string{header})
	if cache.noCache || cache.noStore || !cache.hasMaxAge {
		return 0
	}

	return cache.maxAge
}

func parseCacheControl(headers []string) cacheControl {
	var out cacheControl

	maxAgeCount := 0

	for _, header := range headers {
		for part := range strings.SplitSeq(header, ",") {
			name, value, hasValue := strings.Cut(strings.TrimSpace(part), "=")
			name = strings.TrimSpace(name)

			switch {
			case strings.EqualFold(name, "no-cache"):
				out.noCache = true
			case strings.EqualFold(name, "no-store"):
				out.noStore = true
			case strings.EqualFold(name, "max-age"):
				maxAgeCount++

				out.hasMaxAge = true
				if maxAgeCount == 1 && hasValue {
					out.maxAge = parseDeltaSeconds(value)
				} else {
					out.maxAge = 0
				}
			}
		}
	}

	return out
}

func parseDeltaSeconds(value string) time.Duration {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return 0
		}

		value = unquoted
	}

	secs, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return maxDuration
		}

		return 0
	}

	if secs > uint64(maxDuration/time.Second) {
		return maxDuration
	}

	return time.Duration(secs) * time.Second
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
// Every failure — network, status, size, JSON, policy, or validation — wraps
// ErrKeyFetch; there is no silent fallback to a guessed URL. A nil client uses
// a default client with a 30-second timeout; a supplied client is copied.
//
// The optional policy is applied to the issuer discovery URL, every redirect,
// and the discovered jwks_uri. When omitted, the default rejects direct local
// and private-looking targets. The application MUST preapprove issuer
// hostnames; the default deliberately avoids a DNS lookup that could create a
// check/dial TOCTOU gap.
func DiscoverJWKSURI(ctx context.Context, issuer string, client *http.Client, policies ...URLPolicy) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%w: issuer must be an https URL without query or fragment, got %q", ErrKeyFetch, issuer)
	}

	policy := selectURLPolicy(policies)
	if err := validateURL(u, policy); err != nil {
		return "", err
	}

	discoveryURI := strings.TrimSuffix(issuer, "/") + wellKnownOpenIDConfig

	body, _, err := getCapped(ctx, safeHTTPClient(client, policy), discoveryURI, "application/json", defaultMaxJWKSBytes, policy)
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

	jwksURL, err := url.Parse(doc.JWKSURI)
	if err != nil {
		return "", fmt.Errorf("%w: malformed jwks_uri: %w", ErrKeyFetch, err)
	}

	if err := validateURL(jwksURL, policy); err != nil {
		return "", err
	}

	return doc.JWKSURI, nil
}
