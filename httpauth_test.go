package jwt

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
		wantOK bool
	}{
		{"Bearer abc.def.ghi", "abc.def.ghi", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"", "", false},
		{"Basic abc", "", false},
		{"Bearer ", "", false},
		{"Bearer", "", false},
		{"Bearer a b", "", false},
		{"Bearer \tabc", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		got, ok := BearerToken(r)
		if got != c.want || ok != c.wantOK {
			t.Fatalf("BearerToken(%q) = %q,%v want %q,%v", c.header, got, ok, c.want, c.wantOK)
		}
	}
}

func TestWriteChallenge(t *testing.T) {
	t.Run("no credentials", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteChallenge(w, "api", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", w.Code)
		}
		h := w.Header().Get("WWW-Authenticate")
		if h != `Bearer realm="api"` {
			t.Fatalf("header = %q", h)
		}
	})
	t.Run("invalid token", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteChallenge(w, "", ErrExpired)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", w.Code)
		}
		h := w.Header().Get("WWW-Authenticate")
		if !strings.Contains(h, `error="invalid_token"`) || !strings.Contains(h, "expired") {
			t.Fatalf("header = %q", h)
		}
	})
	t.Run("malformed token is invalid_request 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteChallenge(w, "", ErrMalformedToken)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", w.Code)
		}
		if !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_request"`) {
			t.Fatalf("header = %q", w.Header().Get("WWW-Authenticate"))
		}
	})
	t.Run("quotes are stripped from realm", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteChallenge(w, `ev"il\`, nil)
		h := w.Header().Get("WWW-Authenticate")
		if strings.ContainsAny(strings.TrimPrefix(h, "Bearer realm="), `\`) || strings.Count(h, `"`) != 2 {
			t.Fatalf("unsanitised header = %q", h)
		}
	})
}

func TestMiddleware(t *testing.T) {
	tk := newTestKeys(t)
	signer, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	keys := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))

	var seen *appClaims
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := claimsFromContext[appClaims](r.Context())
		if !ok {
			t.Fatal("claims not in context")
		}
		seen = c
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Middleware(keys, WithAllowedAlgorithms(HS256))(final)

	t.Run("valid token passes through", func(t *testing.T) {
		tok, _ := Sign(appClaims{
			RegisteredClaims: RegisteredClaims{Subject: "u1", ExpiresAt: NewNumericDate(time.Now().Add(time.Hour))},
			Scope:            "read",
		}, signer)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d", w.Code)
		}
		if seen == nil || seen.Subject != "u1" || seen.Scope != "read" {
			t.Fatalf("claims = %+v", seen)
		}
	})

	t.Run("missing token -> 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("status = %d header = %q", w.Code, w.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("expired token -> 401 invalid_token", func(t *testing.T) {
		tok, _ := Sign(appClaims{
			RegisteredClaims: RegisteredClaims{ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour))},
		}, signer)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", w.Code)
		}
		if !strings.Contains(w.Header().Get("WWW-Authenticate"), "invalid_token") {
			t.Fatalf("header = %q", w.Header().Get("WWW-Authenticate"))
		}
	})
}

func TestClaimsFromContextWrongType(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := claimsFromContext[appClaims](r.Context()); ok {
		t.Fatal("expected miss on a bare context")
	}
}
