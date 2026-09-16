package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- redirects (never leave HTTPS) ------------------------------------------

func TestKeyFetcherRejectsRedirectToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer plain.Close()

	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tls.Close()

	err := NewKeyFetcher(tls.URL, WithHTTPClient(tls.Client())).Refresh(context.Background())
	if !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("https->http redirect: err = %v, want ErrKeyFetch", err)
	}
}

func TestKeyFetcherFollowsHTTPSRedirect(t *testing.T) {
	tk := newTestKeys(t)
	body := jwksBytes(t, FromEd25519PublicKey(tk.edPub, "k"))

	var mux http.ServeMux

	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/new", http.StatusMovedPermanently) })
	mux.HandleFunc("/new", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })

	srv := httptest.NewTLSServer(&mux)
	defer srv.Close()

	if _, ok, err := NewKeyFetcher(srv.URL+"/old", WithHTTPClient(srv.Client())).Lookup(context.Background(), "k"); err != nil || !ok {
		t.Fatalf("https->https redirect: ok=%v err=%v", ok, err)
	}
}

func TestKeyFetcherKeepsCallerRedirectPolicyAndDoesNotMutateClient(t *testing.T) {
	var mux http.ServeMux

	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"keys":[]}`)) })

	srv := httptest.NewTLSServer(&mux)
	defer srv.Close()

	errNoRedirects := errors.New("caller forbids redirects")
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errNoRedirects }

	err := NewKeyFetcher(srv.URL+"/a", WithHTTPClient(client)).Refresh(context.Background())
	if !errors.Is(err, errNoRedirects) {
		t.Fatalf("caller CheckRedirect not honored: %v", err)
	}

	if client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(nil, nil), errNoRedirects) {
		t.Fatal("caller's http.Client was mutated")
	}
}

func TestKeyFetcherRedirectLimit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound) //nolint:gosec // test server: endless same-origin redirect loop by design
	}))
	defer srv.Close()

	if err := NewKeyFetcher(srv.URL+"/", WithHTTPClient(srv.Client())).Refresh(context.Background()); !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("endless redirects: %v", err)
	}
}

func TestSafeHTTPClientDefaults(t *testing.T) {
	c := safeHTTPClient(nil)
	if c.Timeout != defaultFetcherTimeout {
		t.Fatalf("default client timeout = %v, want %v", c.Timeout, defaultFetcherTimeout)
	}

	if c.CheckRedirect == nil {
		t.Fatal("default client has no redirect guard")
	}
}

// ---- single-flight, failure backoff, stale serving ---------------------------

func TestKeyFetcherSingleFlightColdStart(t *testing.T) {
	tk := newTestKeys(t)
	body := jwksBytes(t, FromEd25519PublicKey(tk.edPub, "k"))

	var hits atomic.Int32

	release := make(chan struct{})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		<-release

		_, _ = w.Write(body)
	}))
	defer srv.Close()

	f := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client()))

	const n = 100

	var (
		wg    sync.WaitGroup
		found atomic.Int32
	)

	for i := range n {
		wg.Go(func() {
			kid := "k"
			if i%2 == 1 {
				kid = "unknown"
			}

			if _, ok, err := f.Lookup(context.Background(), kid); err == nil && ok {
				found.Add(1)
			}
		})
	}

	time.Sleep(50 * time.Millisecond) // let every goroutine join the flight
	close(release)
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("%d concurrent cold lookups caused %d fetches, want 1", n, got)
	}

	if got := found.Load(); got != n/2 {
		t.Fatalf("found = %d, want %d", got, n/2)
	}
}

func TestKeyFetcherConcurrentRefreshJoinsFlight(t *testing.T) {
	var hits atomic.Int32

	release := make(chan struct{})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		<-release

		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	f := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client()))

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _ = f.Refresh(context.Background()) })
	}

	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("concurrent Refresh caused %d fetches, want 1", got)
	}
}

func TestKeyFetcherFailureBackoff(t *testing.T) {
	var (
		hits    atomic.Int32
		failing atomic.Bool
	)

	failing.Store(true)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)

		if failing.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}

		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	f := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client()))
	base := time.Unix(1_700_000_000, 0)
	f.now = func() time.Time { return base }
	ctx := context.Background()

	for range 50 {
		if _, _, err := f.Lookup(ctx, "k"); !errors.Is(err, ErrKeyFetch) {
			t.Fatalf("failing upstream: err = %v, want ErrKeyFetch", err)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("50 lookups against a failing upstream caused %d fetches, want 1", got)
	}

	// Once minRefresh has elapsed a new attempt is allowed and can recover.
	failing.Store(false)

	f.now = func() time.Time { return base.Add(defaultMinRefresh) }
	if _, ok, err := f.Lookup(ctx, "k"); err != nil || ok {
		t.Fatalf("after backoff: ok=%v err=%v (want not-found, nil)", ok, err)
	}

	if got := hits.Load(); got != 2 {
		t.Fatalf("expected a retry after minRefresh, got %d fetches", got)
	}
}

func TestKeyFetcherServesStaleKeysWhenRefreshFails(t *testing.T) {
	tk := newTestKeys(t)
	body := jwksBytes(t, FromEd25519PublicKey(tk.edPub, "k"))

	var failing atomic.Bool

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}

		_, _ = w.Write(body)
	}))
	defer srv.Close()

	f := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client()))
	base := time.Unix(1_700_000_000, 0)
	f.now = func() time.Time { return base }
	ctx := context.Background()

	if _, ok, err := f.Lookup(ctx, "k"); err != nil || !ok {
		t.Fatalf("warm-up: ok=%v err=%v", ok, err)
	}

	failing.Store(true)

	f.now = func() time.Time { return base.Add(time.Hour) } // document is stale

	if _, ok, err := f.Lookup(ctx, "k"); err != nil || !ok {
		t.Fatalf("stale key not served during outage: ok=%v err=%v", ok, err)
	}

	if _, ok, err := f.Lookup(ctx, "other"); ok || !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("unknown kid during outage: ok=%v err=%v, want ErrKeyFetch", ok, err)
	}
}

func TestKeyFetcherFollowerHonorsOwnContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release

		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))

	defer srv.Close()
	defer close(release)

	f := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client()))

	go func() { _, _, _ = f.Lookup(context.Background(), "k") }() // leader

	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if _, _, err := f.Lookup(ctx, "k"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("follower err = %v, want its own context deadline", err)
	}
}

// ---- Cache-Control max-age cap ------------------------------------------------

func TestKeyFetcherCapsMaxAge(t *testing.T) {
	tk := newTestKeys(t)
	body := jwksBytes(t, FromEd25519PublicKey(tk.edPub, "k"))

	var hits atomic.Int32

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=31536000") // one year
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name string
		opts []FetcherOption
		cap  time.Duration
	}{
		{"default", nil, defaultMaxCacheDuration},
		{"custom", []FetcherOption{WithMaxCacheDuration(time.Hour)}, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)

			f := NewKeyFetcher(srv.URL, append(tc.opts, WithHTTPClient(srv.Client()))...)
			base := time.Unix(1_700_000_000, 0)
			ctx := context.Background()

			for _, step := range []struct {
				at       time.Duration
				wantHits int32
			}{
				{0, 1},
				{tc.cap - time.Second, 1}, // still fresh under the cap
				{tc.cap + time.Second, 2}, // the year-long max-age is not honored past the cap
			} {
				f.now = func() time.Time { return base.Add(step.at) }
				if _, ok, err := f.Lookup(ctx, "k"); err != nil || !ok {
					t.Fatalf("at +%v: ok=%v err=%v", step.at, ok, err)
				}

				if got := hits.Load(); got != step.wantHits {
					t.Fatalf("at +%v: %d fetches, want %d", step.at, got, step.wantHits)
				}
			}
		})
	}
}

func TestWithMaxCacheDurationIgnoresNonPositive(t *testing.T) {
	f := NewKeyFetcher("https://example.test", WithMaxCacheDuration(0), WithMaxCacheDuration(-time.Second))
	if f.maxCache != defaultMaxCacheDuration {
		t.Fatalf("maxCache = %v", f.maxCache)
	}
}

// ---- OIDC discovery (OpenID Connect Discovery 1.0 §4) --------------------------

func discoveryServer(t *testing.T, doc func(issuer string) any) *httptest.Server {
	t.Helper()

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}

		issuer := srv.URL + strings.TrimSuffix(r.URL.Path, "/.well-known/openid-configuration")
		_ = json.NewEncoder(w).Encode(doc(issuer))
	}))
	t.Cleanup(srv.Close)

	return srv
}

func TestDiscoverJWKSURIHappyPaths(t *testing.T) {
	srv := discoveryServer(t, func(iss string) any {
		return map[string]string{"issuer": iss, "jwks_uri": iss + "/keys"}
	})
	ctx := context.Background()

	for _, issuer := range []string{srv.URL, srv.URL + "/tenant/v2.0"} {
		got, err := DiscoverJWKSURI(ctx, issuer, srv.Client())
		if err != nil || got != issuer+"/keys" {
			t.Fatalf("issuer %q: got %q, %v", issuer, got, err)
		}
	}
}

func TestDiscoverJWKSURITrailingSlashIssuer(t *testing.T) {
	// §4.1: a terminating "/" is removed before appending the well-known path,
	// but §4.3 compares the returned issuer with the one requested exactly.
	srv := discoveryServer(t, func(iss string) any {
		return map[string]string{"issuer": iss + "/", "jwks_uri": iss + "/keys"}
	})

	got, err := DiscoverJWKSURI(context.Background(), srv.URL+"/", srv.Client())
	if err != nil || got != srv.URL+"/keys" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDiscoverJWKSURIRejections(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		doc  func(iss string) any
	}{
		{"issuer mismatch", func(string) any {
			return map[string]string{"issuer": "https://evil.example", "jwks_uri": "https://evil.example/keys"}
		}},
		{"issuer missing", func(iss string) any { return map[string]string{"jwks_uri": iss + "/keys"} }},
		{"issuer differs only by trailing slash", func(iss string) any {
			return map[string]string{"issuer": iss + "/", "jwks_uri": iss + "/keys"}
		}},
		{"jwks_uri missing", func(iss string) any { return map[string]string{"issuer": iss} }},
		{"jwks_uri not https", func(iss string) any {
			return map[string]string{"issuer": iss, "jwks_uri": "http://insecure.example/keys"}
		}},
		{"not a JSON object", func(string) any { return []int{1, 2} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := discoveryServer(t, tc.doc)
			if got, err := DiscoverJWKSURI(ctx, srv.URL, srv.Client()); !errors.Is(err, ErrKeyFetch) {
				t.Fatalf("got %q, err = %v, want ErrKeyFetch", got, err)
			}
		})
	}
}

func TestDiscoverJWKSURINoSilentFallback(t *testing.T) {
	ctx := context.Background()

	notFound := httptest.NewTLSServer(http.NotFoundHandler())
	defer notFound.Close()

	if got, err := DiscoverJWKSURI(ctx, notFound.URL, notFound.Client()); !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("404 discovery: got %q, err = %v", got, err)
	}

	unreachable := httptest.NewTLSServer(http.NotFoundHandler())
	url, client := unreachable.URL, unreachable.Client()
	unreachable.Close()

	if got, err := DiscoverJWKSURI(ctx, url, client); !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("network failure: got %q, err = %v", got, err)
	}
}

func TestDiscoverJWKSURIInputValidation(t *testing.T) {
	ctx := context.Background()

	for _, issuer := range []string{"", "/", "http://issuer.example", "ftp://issuer.example", "://bad", "https://issuer.example?x=1", "https://issuer.example#frag"} {
		if _, err := DiscoverJWKSURI(ctx, issuer, nil); !errors.Is(err, ErrKeyFetch) {
			t.Fatalf("issuer %q: err = %v, want ErrKeyFetch", issuer, err)
		}
	}
}

func TestDiscoverJWKSURIBodyCap(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("a", defaultMaxJWKSBytes) + `"}`))
	}))
	defer srv.Close()

	if _, err := DiscoverJWKSURI(context.Background(), srv.URL, srv.Client()); !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("oversized discovery document: %v", err)
	}
}

func TestDiscoverJWKSURIRejectsRedirectToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound) //nolint:gosec // test server: deliberate downgrade redirect
	}))
	defer srv.Close()

	if _, err := DiscoverJWKSURI(context.Background(), srv.URL, srv.Client()); !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("redirect to http: %v", err)
	}
}
