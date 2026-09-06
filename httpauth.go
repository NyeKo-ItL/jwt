package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// BearerToken extracts the credential from an "Authorization: Bearer <token>"
// header (RFC 6750 §2.1). The scheme match is case-insensitive; exactly one
// space separates it from the token, which must be non-empty and contain no
// whitespace.
func BearerToken(r *http.Request) (string, bool) {
	const scheme = "bearer "
	h := r.Header.Get("Authorization")
	if len(h) < len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", false
	}
	token := h[len(scheme):]
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

type claimsContextKey struct{}

// ClaimsFromContext retrieves the *Claims[T] that Middleware injected. The
// type parameter must match the one Middleware was instantiated with.
func ClaimsFromContext[T any](ctx context.Context) (*Claims[T], bool) {
	v, ok := ctx.Value(claimsContextKey{}).(*Claims[T])
	return v, ok
}

// Middleware verifies the request's bearer token with keys and opts and puts
// the resulting claims in the request context (retrieve them with
// ClaimsFromContext[T]). On any failure it writes an RFC 6750 §3 challenge
// via WriteChallenge and does not call next.
func Middleware[T any](keys KeyProvider, opts ...ParseOption) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := BearerToken(r)
			if !ok {
				WriteChallenge(w, "", nil)
				return
			}
			claims, err := Parse[T](r.Context(), token, keys, opts...)
			if err != nil {
				WriteChallenge(w, "", err)
				return
			}
			ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WriteChallenge writes a "WWW-Authenticate: Bearer" response header per
// RFC 6750 §3 and sets the matching status code. A nil err yields a bare
// challenge (401, no error code) — the "credentials required" case.
// ErrMalformedToken maps to error="invalid_request" (400); every other
// verification failure maps to error="invalid_token" (401).
func WriteChallenge(w http.ResponseWriter, realm string, err error) {
	params := make([]string, 0, 3)
	if realm != "" {
		params = append(params, fmt.Sprintf("realm=%q", quoteSafe(realm)))
	}

	status := http.StatusUnauthorized
	switch {
	case err == nil:
		// bare challenge
	case errors.Is(err, ErrMalformedToken):
		status = http.StatusBadRequest
		params = append(params, `error="invalid_request"`,
			fmt.Sprintf("error_description=%q", quoteSafe(err.Error())))
	default:
		params = append(params, `error="invalid_token"`,
			fmt.Sprintf("error_description=%q", quoteSafe(err.Error())))
	}

	challenge := "Bearer"
	if len(params) > 0 {
		challenge += " " + strings.Join(params, ", ")
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintln(w, http.StatusText(status))
}

// quoteSafe strips the characters that may not appear inside an RFC 7235
// quoted-string (backslash, double quote) plus control characters, so the
// result can be wrapped in quotes without further escaping.
func quoteSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
