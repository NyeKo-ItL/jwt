package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- RFC 6750 §2.1 credential syntax ------------------------------------------------

func TestBearerTokenSyntax(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		// b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
		{"Bearer abc.DEF-ghi_jkl~mno+pqr/stu", "abc.DEF-ghi_jkl~mno+pqr/stu", true},
		{"Bearer mF_9.B5f-4.1JqM", "mF_9.B5f-4.1JqM", true}, // RFC 6750 §2.1 example
		{"Bearer abc==", "abc==", true},
		{"Bearer  abc", "abc", true}, // credentials = "Bearer" 1*SP b64token
		{"Bearer   abc", "abc", true},
		{"Bearer =abc", "", false}, // "=" only as trailing padding
		{"Bearer ab=c", "", false},
		{"Bearer ab\"c", "", false},
		{"Bearer ab,c", "", false},
		{"Bearer ab;c", "", false},
		{"Bearer ab%2Ec", "", false},
		{"Bearer ab\x00c", "", false},
		{"Bearer é", "", false},
		{"Bearer\tabc", "", false}, // SP only, not HTAB
		{"Bearerabc", "", false},
		{"Bearer abc def", "", false},
		{"Bearer ===", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header["Authorization"] = []string{c.header}

		got, ok := BearerToken(r)
		if got != c.want || ok != c.ok {
			t.Errorf("BearerToken(%q) = %q, %v; want %q, %v", c.header, got, ok, c.want, c.ok)
		}
	}
}

func TestBearerTokenRejectsMultipleAuthorizationHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Authorization", "Bearer a")
	r.Header.Add("Authorization", "Bearer b")

	if tok, ok := BearerToken(r); ok {
		t.Fatalf("ambiguous credentials accepted: %q", tok)
	}
}

// ---- RFC 6750 §3 challenges without internal detail ---------------------------------------

type leakyError struct{}

func (leakyError) Error() string { return "dial tcp 10.1.2.3:6379: i/o timeout (redis-internal.corp)" }

func TestWriteChallengeMapping(t *testing.T) {
	secret := "10.1.2.3"

	cases := []struct {
		name       string
		err        error
		status     int
		challenge  bool
		errorCode  string
		descSubstr string
	}{
		{"nil", nil, 401, true, "", ""},
		{"malformed", fmt.Errorf("%w: header JSON: %s", ErrMalformedToken, secret), 400, true, "invalid_request", "malformed"},
		{"expired", ErrExpired, 401, true, "invalid_token", "expired"},
		{"not yet valid", ErrNotYetValid, 401, true, "invalid_token", "not yet valid"},
		{"bad signature", ErrInvalidSignature, 401, true, "invalid_token", "invalid"},
		{"issuer", fmt.Errorf("%w (%s)", ErrIssuerMismatch, secret), 401, true, "invalid_token", "invalid"},
		{"audience", ErrAudienceMismatch, 401, true, "invalid_token", "invalid"},
		{"alg", ErrAlgorithmNotAllowed, 401, true, "invalid_token", "invalid"},
		{"typ", ErrTypeMismatch, 401, true, "invalid_token", "invalid"},
		{"missing claim", ErrMissingClaim, 401, true, "invalid_token", "invalid"},
		{"unknown kid", ErrKeyNotFound, 401, true, "invalid_token", "invalid"},
		{"key usage", ErrKeyUsage, 401, true, "invalid_token", "invalid"},
		{"key type", ErrKeyTypeMismatch, 401, true, "invalid_token", "invalid"},
		{"crit", ErrUnsupportedCritical, 401, true, "invalid_token", "invalid"},
		{"unsupported alg", ErrUnsupportedAlgorithm, 401, true, "invalid_token", "invalid"},
		{"decryption", ErrDecryptionFailed, 401, true, "invalid_token", "invalid"},
		{"JWKS unreachable", fmt.Errorf("%w: Get https://%s/jwks", ErrKeyFetch, secret), 503, false, "", ""},
		{"context deadline", fmt.Errorf("lookup: %w", context.DeadlineExceeded), 503, false, "", ""},
		{"misconfiguration", ErrNoAllowedAlgorithms, 500, false, "", ""},
		{"unknown backend error", leakyError{}, 500, false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriteChallenge(w, "api", tc.err)

			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}

			h := w.Header().Get("WWW-Authenticate")
			if tc.challenge != (h != "") {
				t.Fatalf("WWW-Authenticate = %q, want present=%v", h, tc.challenge)
			}

			if tc.errorCode != "" && !strings.Contains(h, `error="`+tc.errorCode+`"`) {
				t.Fatalf("WWW-Authenticate = %q, want error=%q", h, tc.errorCode)
			}

			if tc.descSubstr != "" && !strings.Contains(h, tc.descSubstr) {
				t.Fatalf("WWW-Authenticate = %q, want description containing %q", h, tc.descSubstr)
			}

			for _, leak := range []string{secret, "jwt:", "redis", "dial tcp"} {
				if strings.Contains(h, leak) || strings.Contains(w.Body.String(), leak) {
					t.Fatalf("response leaks %q: header=%q body=%q", leak, h, w.Body.String())
				}
			}
		})
	}
}

func TestWriteInsufficientScope(t *testing.T) {
	w := httptest.NewRecorder()
	WriteInsufficientScope(w, "api", "orders:read", "orders:write")

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d", w.Code)
	}

	want := `Bearer realm="api", error="insufficient_scope", scope="orders:read orders:write"`
	if h := w.Header().Get("WWW-Authenticate"); h != want {
		t.Fatalf("WWW-Authenticate = %q\n                  want %q", h, want)
	}

	// scope-token = 1*( %x21 / %x23-5B / %x5D-7E ) (RFC 6749 §3.3): anything
	// else is dropped rather than injected into the quoted-string.
	w = httptest.NewRecorder()
	WriteInsufficientScope(w, "", `ok`, `bad"quote`, `bad\slash`, `sp ace`, "")

	if h := w.Header().Get("WWW-Authenticate"); h != `Bearer error="insufficient_scope", scope="ok"` {
		t.Fatalf("WWW-Authenticate = %q", h)
	}
}

// ---- Middleware: options, error hook, status classes ---------------------------------------

func TestMiddlewareInfrastructureFailureIs503AndReported(t *testing.T) {
	tk := newTestKeys(t)
	signer, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	tok, _ := Sign(appClaims{}, signer)

	backendErr := fmt.Errorf("%w: dial tcp 10.9.9.9:443", ErrKeyFetch)
	keys := keyProviderFunc(func(string) (Key, bool, error) { return Key{}, false, backendErr })

	var reported error

	h := Middleware(keys, WithAllowedAlgorithms(HS256),
		MiddlewareOptions{Realm: "orders", OnError: func(_ *http.Request, err error) { reported = err }},
	)(http.NotFoundHandler())

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("status = %d, WWW-Authenticate = %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}

	if strings.Contains(w.Body.String(), "10.9.9.9") {
		t.Fatalf("body leaks backend detail: %q", w.Body.String())
	}

	if !errors.Is(reported, ErrKeyFetch) || !strings.Contains(reported.Error(), "10.9.9.9") {
		t.Fatalf("OnError got %v, want the full error", reported)
	}
}

func TestMiddlewareRealmAndReporting(t *testing.T) {
	tk := newTestKeys(t)
	signer, _ := NewHMACSigner(HS256, tk.hmac)
	keys := StaticKeyProvider(FromHMACSecret(tk.hmac))
	expired, _ := Sign(appClaims{RegisteredClaims: RegisteredClaims{ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour))}}, signer)

	var calls []error

	h := Middleware(keys, WithAllowedAlgorithms(HS256),
		MiddlewareOptions{Realm: "orders", OnError: func(_ *http.Request, err error) { calls = append(calls, err) }},
	)(http.NotFoundHandler())

	for _, tc := range []struct {
		auth      string
		wantErr   error
		challenge string
	}{
		{"", nil, `Bearer realm="orders"`},
		{"Bearer " + expired, ErrExpired, `Bearer realm="orders", error="invalid_token", error_description="The access token expired"`},
		{"Bearer bad.token", ErrMalformedToken, `Bearer realm="orders", error="invalid_request", error_description="The access token is malformed"`},
	} {
		calls = nil
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}

		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if got := w.Header().Get("WWW-Authenticate"); got != tc.challenge {
			t.Errorf("auth %.20q: WWW-Authenticate = %q, want %q", tc.auth, got, tc.challenge)
		}

		if tc.wantErr != nil && (len(calls) != 1 || !errors.Is(calls[0], tc.wantErr)) {
			t.Errorf("auth %.20q: OnError calls = %v", tc.auth, calls)
		}
	}
}

func TestMiddlewareMisconfigurationIs500(t *testing.T) {
	keys := StaticKeyProvider(FromHMACSecret(make([]byte, 32)))
	h := Middleware(keys)(http.NotFoundHandler()) // no allowlist

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abc.def.ghi")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "WithAllowedAlgorithms") {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
}

func TestMiddlewareOptionsIgnoredByParse(t *testing.T) {
	key, keys := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256"}`, `{}`)

	if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256), MiddlewareOptions{Realm: "x"}); err != nil {
		t.Fatalf("Parse with MiddlewareOptions: %v", err)
	}
}
