package jwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestV1FetchMaxStaleDurationFailsClosed(t *testing.T) {
	tk := newTestKeys(t)
	body := jwksBytes(t, FromEd25519PublicKey(tk.edPub, "k"))

	var failing atomic.Bool

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	base := time.Unix(1_700_000_000, 0)
	f := NewKeyFetcher(
		srv.URL,
		WithHTTPClient(srv.Client()),
		WithURLPolicy(allowTestURL),
		WithMinRefreshInterval(time.Second),
		WithMaxStaleDuration(2*time.Hour),
	)
	f.now = func() time.Time { return base }

	if _, ok, err := f.Lookup(context.Background(), "k"); err != nil || !ok {
		t.Fatalf("warm-up: ok=%v err=%v", ok, err)
	}

	failing.Store(true)

	f.now = func() time.Time { return base.Add(time.Minute) }
	if _, ok, err := f.Lookup(context.Background(), "k"); err != nil || !ok {
		t.Fatalf("inside stale window: ok=%v err=%v", ok, err)
	}

	f.now = func() time.Time { return base.Add(2*time.Hour + time.Minute) }
	if _, ok, err := f.Lookup(context.Background(), "k"); ok || !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("at stale limit: ok=%v err=%v, want fail-closed", ok, err)
	}
}

func TestV1FetchZeroMaxStaleDisablesFallback(t *testing.T) {
	tk := newTestKeys(t)
	body := jwksBytes(t, FromEd25519PublicKey(tk.edPub, "k"))

	var failing atomic.Bool

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	base := time.Unix(1_700_000_000, 0)
	f := NewKeyFetcher(
		srv.URL,
		WithHTTPClient(srv.Client()),
		WithURLPolicy(allowTestURL),
		WithMinRefreshInterval(time.Second),
		WithMaxStaleDuration(0),
	)

	f.now = func() time.Time { return base }
	if _, ok, err := f.Lookup(context.Background(), "k"); err != nil || !ok {
		t.Fatalf("warm-up: ok=%v err=%v", ok, err)
	}

	failing.Store(true)

	f.now = func() time.Time { return base.Add(time.Second) }
	if _, ok, err := f.Lookup(context.Background(), "k"); ok || !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("stale fallback not disabled: ok=%v err=%v", ok, err)
	}
}

func TestV1FetchCacheControlDirectives(t *testing.T) {
	tk := newTestKeys(t)
	body := jwksBytes(t, FromEd25519PublicKey(tk.edPub, "k"))

	for _, tc := range []struct {
		name      string
		header    string
		wantStore bool
	}{
		{name: "no-cache case insensitive", header: "public, MAX-AGE=3600, No-CaChE", wantStore: true},
		{name: "no-store case insensitive", header: "MAX-AGE=3600, NO-STORE", wantStore: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32

			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Cache-Control", tc.header)
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			base := time.Unix(1_700_000_000, 0)
			f := NewKeyFetcher(
				srv.URL,
				WithHTTPClient(srv.Client()),
				WithURLPolicy(allowTestURL),
				WithMinRefreshInterval(time.Second),
			)

			f.now = func() time.Time { return base }
			if _, ok, err := f.Lookup(context.Background(), "k"); err != nil || !ok {
				t.Fatalf("first lookup: ok=%v err=%v", ok, err)
			}

			if (f.set != nil) != tc.wantStore {
				t.Fatalf("retained=%v, want %v", f.set != nil, tc.wantStore)
			}

			f.now = func() time.Time { return base.Add(2 * time.Second) }
			if _, ok, err := f.Lookup(context.Background(), "k"); err != nil || !ok {
				t.Fatalf("second lookup: ok=%v err=%v", ok, err)
			}

			if got := hits.Load(); got != 2 {
				t.Fatalf("directive incorrectly made response fresh: hits=%d", got)
			}
		})
	}
}

func TestV1FetchMaxAgeParsingIsRobust(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{header: "MaX-AgE=12", want: 12 * time.Second},
		{header: `max-age="13"`, want: 13 * time.Second},
		{header: "max-age=184467440737095516160", want: maxDuration},
		{header: "max-age=-1", want: 0},
		{header: "max-age=12, MAX-AGE=13", want: 0},
		{header: "max-age=12, NO-CACHE", want: 0},
	} {
		if got := parseMaxAge(tc.header); got != tc.want {
			t.Errorf("parseMaxAge(%q)=%v, want %v", tc.header, got, tc.want)
		}
	}
}

func TestV1FetchNilOptionsAndKeyCountCap(t *testing.T) {
	f := NewKeyFetcher("https://issuer.example/keys", nil, WithURLPolicy(nil))
	if f == nil {
		t.Fatal("nil fetcher")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{},{}]}`))
	}))
	defer srv.Close()

	err := NewKeyFetcher(
		srv.URL,
		WithHTTPClient(srv.Client()),
		WithURLPolicy(allowTestURL),
		WithMaxKeyCount(1),
	).Refresh(context.Background())
	if !errors.Is(err, ErrKeyFetch) || !strings.Contains(err.Error(), "limit is 1") {
		t.Fatalf("key-count limit: %v", err)
	}
}

func TestV1FetchURLPolicyCoversInitialAndRedirects(t *testing.T) {
	var targetHits atomic.Int32

	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)

		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer target.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}

	allowOriginOnly := func(u *url.URL) error {
		if u.Host != originURL.Host {
			return errors.New("host is not preapproved")
		}

		return nil
	}

	f := NewKeyFetcher(origin.URL, WithHTTPClient(origin.Client()), WithURLPolicy(allowOriginOnly))
	if err := f.Refresh(context.Background()); !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("redirect policy error=%v", err)
	}

	if got := targetHits.Load(); got != 0 {
		t.Fatalf("redirect target was reached %d times", got)
	}

	var initialHits atomic.Int32

	blocked := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		initialHits.Add(1)
	}))
	defer blocked.Close()

	if err := NewKeyFetcher(blocked.URL, WithHTTPClient(blocked.Client())).Refresh(context.Background()); !errors.Is(err, ErrKeyFetch) {
		t.Fatalf("default initial policy error=%v", err)
	}

	if got := initialHits.Load(); got != 0 {
		t.Fatalf("blocked initial URL was reached %d times", got)
	}
}
