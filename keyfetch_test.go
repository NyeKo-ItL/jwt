package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func jwksBytes(t *testing.T, keys ...Key) []byte {
	t.Helper()
	b, err := json.Marshal(NewKeySet(keys...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeyFetcherLookupAndCache(t *testing.T) {
	tk := newTestKeys(t)
	var hits atomic.Int32
	body := jwksBytes(t, FromRSAPublicKey(&tk.rsa2048.PublicKey, "k1"))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	f := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client()))
	base := time.Unix(1_700_000_000, 0)
	f.now = func() time.Time { return base }
	ctx := context.Background()

	if k, ok, err := f.Lookup(ctx, "k1"); err != nil || !ok || k.Kty != KeyTypeRSA {
		t.Fatalf("first lookup: %v %v %v", k.Kty, ok, err)
	}
	if _, ok, _ := f.Lookup(ctx, "k1"); !ok {
		t.Fatal("second lookup failed")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 network hit while cache fresh, got %d", got)
	}

	// a cache miss within minRefresh must not trigger a refetch
	if _, ok, _ := f.Lookup(ctx, "unknown"); ok {
		t.Fatal("unknown kid resolved")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("cache-miss inside minRefresh refetched: %d hits", got)
	}

	// advance past minRefresh: a miss now refetches
	f.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, ok, _ := f.Lookup(ctx, "unknown"); ok {
		t.Fatal("unknown kid resolved after refresh")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("expected refetch after minRefresh, got %d hits", got)
	}
}

func TestKeyFetcherRefreshPicksUpRotation(t *testing.T) {
	tk := newTestKeys(t)
	current := jwksBytes(t, FromRSAPublicKey(&tk.rsa2048.PublicKey, "old"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(current)
	}))
	defer srv.Close()

	f := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client()))
	ctx := context.Background()
	if _, ok, _ := f.Lookup(ctx, "old"); !ok {
		t.Fatal("old key not found")
	}

	current = jwksBytes(t, FromECDSAPublicKey(&tk.p256.PublicKey, "new"))
	if err := f.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if k, ok, _ := f.Lookup(ctx, "new"); !ok || k.Kty != KeyTypeEC {
		t.Fatalf("rotated key not found: %v %v", k.Kty, ok)
	}
}

func TestKeyFetcherHonorsMaxAge(t *testing.T) {
	tk := newTestKeys(t)
	var hits atomic.Int32
	body := jwksBytes(t, FromRSAPublicKey(&tk.rsa2048.PublicKey, "k1"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	f := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client()), WithMinRefreshInterval(time.Second))
	base := time.Unix(1_700_000_000, 0)
	f.now = func() time.Time { return base }
	ctx := context.Background()

	_, _, _ = f.Lookup(ctx, "k1")
	// 10 minutes later — still inside the 1h max-age, so no refetch even though
	// minRefresh is only 1s.
	f.now = func() time.Time { return base.Add(10 * time.Minute) }
	_, _, _ = f.Lookup(ctx, "k1")
	if got := hits.Load(); got != 1 {
		t.Fatalf("max-age not honored: %d hits", got)
	}
}

func TestKeyFetcherErrors(t *testing.T) {
	ctx := context.Background()

	if err := NewKeyFetcher("http://insecure.example/jwks").Refresh(ctx); err == nil {
		t.Fatal("expected https-only rejection")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client())).Refresh(ctx); err == nil {
		t.Fatal("expected non-200 error")
	}

	big := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 4096))
	}))
	defer big.Close()
	f := NewKeyFetcher(big.URL, WithHTTPClient(big.Client()), WithMaxResponseBytes(1024))
	if _, _, err := f.Lookup(ctx, "x"); err == nil {
		t.Fatal("expected size-cap error")
	}
}

func TestParseMaxAge(t *testing.T) {
	cases := map[string]time.Duration{
		"":                         0,
		"no-store":                 0,
		"max-age=600":              600 * time.Second,
		"public, max-age=120, foo": 120 * time.Second,
		"max-age=0":                0,
		"max-age=abc":              0,
	}
	for in, want := range cases {
		if got := parseMaxAge(in); got != want {
			t.Fatalf("parseMaxAge(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDiscoverJWKSURI(t *testing.T) {
	ctx := context.Background()

	var mux http.ServeMux
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "https://issuer.example/keys"})
	})
	srv := httptest.NewTLSServer(&mux)
	defer srv.Close()

	got, err := DiscoverJWKSURI(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://issuer.example/keys" {
		t.Fatalf("discovered %q", got)
	}

	// no discovery doc -> conventional fallback
	blank := httptest.NewTLSServer(http.NotFoundHandler())
	defer blank.Close()
	got, err = DiscoverJWKSURI(ctx, blank.URL+"/", blank.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got != blank.URL+"/.well-known/jwks.json" {
		t.Fatalf("fallback = %q", got)
	}

	if _, err := DiscoverJWKSURI(ctx, "", nil); err == nil {
		t.Fatal("expected empty-issuer error")
	}
}

func TestKeyFetcherRejectsBadBodyAndURL(t *testing.T) {
	ctx := context.Background()

	if err := NewKeyFetcher("://not-a-url").Refresh(ctx); err == nil {
		t.Fatal("expected parse error for malformed URL")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":"not an array"}`))
	}))
	defer srv.Close()
	if err := NewKeyFetcher(srv.URL, WithHTTPClient(srv.Client())).Refresh(ctx); err == nil {
		t.Fatal("expected error for malformed JWKS body")
	}
}
