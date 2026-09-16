package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// BearerToken extracts the credential from an "Authorization: Bearer <token>"
// header (RFC 6750 §2.1). The scheme matches case-insensitively (RFC 9110
// §11.1) and is followed by one or more spaces; the token must match the
// b64token syntax: 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" )
// *"=". A request with several Authorization headers is rejected as
// ambiguous. The form-body and URI-query methods (§2.2–2.3) are not
// supported.
func BearerToken(r *http.Request) (string, bool) {
	const scheme = "bearer"

	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}

	h := values[0]
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) || h[len(scheme)] != ' ' {
		return "", false
	}

	token := strings.TrimLeft(h[len(scheme):], " ")
	if !isB64Token(token) {
		return "", false
	}

	return token, true
}

// isB64Token reports whether s matches RFC 6750 §2.1 b64token.
func isB64Token(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}

	for i := range len(body) {
		if !isB64TokenChar(body[i]) {
			return false
		}
	}

	return true
}

func isB64TokenChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	default:
		return strings.IndexByte("-._~+/", c) >= 0
	}
}

type claimsContextKey struct{}

// ErrNoClaimsInContext is returned by ClaimsFromContext when the request did
// not pass through Middleware.
var ErrNoClaimsInContext = errors.New("jwt: no verified claims in context")

// ClaimsFromContext unmarshals the verified payload that Middleware stored on
// the request context into dst (a pointer to any claims struct; its type is
// inferred, so no explicit type argument):
//
//	var claims MyClaims
//	if err := jwt.ClaimsFromContext(r.Context(), &claims); err != nil { ... }
func ClaimsFromContext[C any](ctx context.Context, dst *C) error {
	payload, ok := ctx.Value(claimsContextKey{}).([]byte)
	if !ok {
		return ErrNoClaimsInContext
	}

	if err := decodeObject(payload, dst); err != nil {
		return fmt.Errorf("%w: payload JSON: %w", ErrMalformedToken, err)
	}

	return nil
}

// MiddlewareOptions configures Middleware. It satisfies ParseOption so it can
// be passed alongside the parse options; Parse and DecryptClaims ignore it.
type MiddlewareOptions struct {
	// Realm is sent as the "realm" challenge attribute (RFC 6750 §3).
	Realm string
	// OnError, when set, receives every verification failure with its full
	// detail, for logging. Clients only ever see the fixed, non-revealing
	// responses documented on WriteChallenge.
	OnError func(r *http.Request, err error)
}

func (o MiddlewareOptions) applyParse(c *parseConfig) {
	if o.Realm != "" {
		c.middleware.Realm = o.Realm
	}

	if o.OnError != nil {
		c.middleware.OnError = o.OnError
	}
}

// Middleware verifies the request's bearer token with keys and opts, then
// stores the verified payload on the request context for ClaimsFromContext
// to decode. On failure it does not call next: it reports the error to
// MiddlewareOptions.OnError (if set) and answers via WriteChallenge — 401/400
// with an RFC 6750 §3 challenge for token problems, 503 or 500 without
// details for infrastructure or configuration problems.
func Middleware(keys KeyProvider, opts ...ParseOption) func(http.Handler) http.Handler {
	cfg := parseConfig{now: time.Now}
	for _, o := range opts {
		o.applyParse(&cfg)
	}

	mw := cfg.middleware

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := BearerToken(r)
			if !ok {
				WriteChallenge(w, mw.Realm, nil)
				return
			}

			payload, err := parseVerified(r.Context(), token, keys, cfg)
			if err != nil {
				if mw.OnError != nil {
					mw.OnError(r, err)
				}

				WriteChallenge(w, mw.Realm, err)

				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey{}, payload)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// tokenErrors are the failures attributable to the presented token itself;
// they map to RFC 6750 "invalid_token".
var tokenErrors = []error{
	ErrInvalidSignature, ErrExpired, ErrNotYetValid, ErrIssuerMismatch, ErrAudienceMismatch,
	ErrAlgorithmNotAllowed, ErrMissingClaim, ErrTypeMismatch, ErrKeyNotFound, ErrKeyUsage,
	ErrKeyTypeMismatch, ErrUnsupportedCritical, ErrUnsupportedAlgorithm, ErrDecryptionFailed,
}

// WriteChallenge answers a failed bearer authentication. Responses carry only
// fixed text, never err's message, so internal detail (hostnames, backend
// errors) cannot leak to clients:
//
//   - nil: 401 with a bare "WWW-Authenticate: Bearer" challenge — credentials
//     required (RFC 6750 §3.1, no error code);
//   - ErrMalformedToken: 400, error="invalid_request";
//   - a token failure (bad signature, expired, wrong issuer/audience, unknown
//     kid, disallowed algorithm, ...): 401, error="invalid_token", with a
//     generic error_description ("expired" and "not yet valid" are named);
//   - ErrKeyFetch or a context cancellation/deadline: 503, no challenge;
//   - anything else (misconfiguration such as ErrNoAllowedAlgorithms, a
//     KeyProvider backend failure, a broken stored key): 500, no challenge.
//
// realm, when non-empty, is included in challenges with quotes, backslashes
// and control characters removed.
func WriteChallenge(w http.ResponseWriter, realm string, err error) {
	status, code, desc := classifyAuthError(err)
	if status >= http.StatusInternalServerError {
		writeStatus(w, status)
		return
	}

	params := make([]string, 0, 3)
	if realm != "" {
		params = append(params, fmt.Sprintf("realm=%q", quoteSafe(realm)))
	}

	if code != "" {
		params = append(params, fmt.Sprintf("error=%q", code), fmt.Sprintf("error_description=%q", desc))
	}

	writeBearerChallenge(w, status, params)
}

// WriteInsufficientScope writes the RFC 6750 §3.1 "insufficient_scope"
// response (403) for a valid token that lacks the scopes a resource needs.
// Scope values that are not RFC 6749 §3.3 scope-tokens are omitted.
func WriteInsufficientScope(w http.ResponseWriter, realm string, scopes ...string) {
	params := make([]string, 0, 3)
	if realm != "" {
		params = append(params, fmt.Sprintf("realm=%q", quoteSafe(realm)))
	}

	params = append(params, `error="insufficient_scope"`)

	valid := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if isScopeToken(sc) {
			valid = append(valid, sc)
		}
	}

	if len(valid) > 0 {
		params = append(params, `scope="`+strings.Join(valid, " ")+`"`)
	}

	writeBearerChallenge(w, http.StatusForbidden, params)
}

func classifyAuthError(err error) (status int, code, desc string) {
	switch {
	case err == nil:
		return http.StatusUnauthorized, "", ""
	case errors.Is(err, ErrKeyFetch), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable, "", ""
	case errors.Is(err, ErrMalformedToken):
		return http.StatusBadRequest, "invalid_request", "The access token is malformed"
	case errors.Is(err, ErrExpired):
		return http.StatusUnauthorized, "invalid_token", "The access token expired"
	case errors.Is(err, ErrNotYetValid):
		return http.StatusUnauthorized, "invalid_token", "The access token is not yet valid"
	}

	for _, target := range tokenErrors {
		if errors.Is(err, target) {
			return http.StatusUnauthorized, "invalid_token", "The access token is invalid"
		}
	}

	return http.StatusInternalServerError, "", ""
}

func writeBearerChallenge(w http.ResponseWriter, status int, params []string) {
	challenge := "Bearer"
	if len(params) > 0 {
		challenge += " " + strings.Join(params, ", ")
	}

	w.Header().Set("WWW-Authenticate", challenge)
	writeStatus(w, status)
}

func writeStatus(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintln(w, http.StatusText(status))
}

// isScopeToken reports whether s is an RFC 6749 §3.3 scope-token:
// 1*( %x21 / %x23-5B / %x5D-7E ).
func isScopeToken(s string) bool {
	if s == "" {
		return false
	}

	for i := range len(s) {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}

	return true
}

// quoteSafe strips the characters that may not appear inside an RFC 9110
// quoted-string without escaping (backslash, double quote) plus control
// characters, so the result can be wrapped in quotes as-is.
func quoteSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return -1
		}

		return r
	}, s)
}
