package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// maxTokenBytes bounds the input accepted by Parse / ParseInsecure so a
// malformed or hostile token cannot force unbounded work (spec §4.11).
const maxTokenBytes = 1 << 20 // 1 MiB

// Sentinel errors. All are comparable with errors.Is (spec §6.3).
var (
	ErrInvalidSignature    = errors.New("jwt: invalid signature")
	ErrExpired             = errors.New("jwt: token expired")
	ErrNotYetValid         = errors.New("jwt: token not yet valid")
	ErrIssuerMismatch      = errors.New("jwt: issuer mismatch")
	ErrAudienceMismatch    = errors.New("jwt: audience mismatch")
	ErrAlgorithmNotAllowed = errors.New("jwt: algorithm not in allowlist")
	ErrNoAllowedAlgorithms = errors.New("jwt: WithAllowedAlgorithms is required")
	ErrMissingClaim        = errors.New("jwt: required claim missing")
	ErrMalformedToken      = errors.New("jwt: malformed token")
	ErrTypeMismatch        = errors.New("jwt: unexpected \"typ\" header")

	// Sentinels beyond the §5.1 list, needed by the constructors and the
	// key-resolution path.
	ErrWeakKey              = errors.New("jwt: key does not meet minimum size")
	ErrUnsupportedAlgorithm = errors.New("jwt: unsupported algorithm")
	ErrKeyNotFound          = errors.New("jwt: no key for kid")
	ErrKeyTypeMismatch      = errors.New("jwt: key type does not match algorithm")
	ErrMalformedKey         = errors.New("jwt: malformed key material")
	ErrOctNotServable       = errors.New("jwt: oct keys must not be serialized into a JWKS document")
)

// DefaultType is the "typ" header value Sign stamps on every token it
// produces: the RFC 7519 §5.1 recommended media type, also satisfying the
// explicit-typing guidance of RFC 8725 §3.11. Profiles that need a
// different value (e.g. RFC 9068's "at+jwt") mint the header themselves.
const DefaultType = "JWT"

// Sign encodes claims and produces a compact JWS (RFC 7515 §7.1). The
// generated header carries "alg", "typ" (DefaultType), and — when the
// signer has one — "kid".
func Sign[T any](claims Claims[T], signer Signer) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("%w: nil signer", ErrUnsupportedAlgorithm)
	}
	alg := signer.Algorithm()
	if alg == "" || strings.EqualFold(string(alg), "none") {
		return "", fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, alg)
	}
	headerJSON, err := json.Marshal(Header{Algorithm: alg, Type: DefaultType, KeyID: signer.KeyID()})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64.Encode(headerJSON) + "." + b64.Encode(payloadJSON)
	sig, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.Encode(sig), nil
}

// Parse decodes a compact JWS, verifies its signature with a key resolved
// from keys, and validates the registered claims per opts.
// WithAllowedAlgorithms is mandatory (RFC 8725 §3.1); Parse returns
// ErrNoAllowedAlgorithms if no usable algorithm is supplied.
func Parse[T any](ctx context.Context, token string, keys KeyProvider, opts ...ParseOption) (*Claims[T], error) {
	cfg := parseConfig{now: time.Now}
	for _, o := range opts {
		o(&cfg)
	}
	allowed := withoutNone(cfg.allowedAlgs)
	if len(allowed) == 0 {
		return nil, ErrNoAllowedAlgorithms
	}
	if keys == nil {
		return nil, fmt.Errorf("%w: nil KeyProvider", ErrKeyNotFound)
	}
	if len(token) > maxTokenBytes {
		return nil, fmt.Errorf("%w: token exceeds %d bytes", ErrMalformedToken, maxTokenBytes)
	}

	h, p, s, ok := split3(token)
	if !ok {
		return nil, fmt.Errorf("%w: expected three '.'-separated segments", ErrMalformedToken)
	}
	headerJSON, err := b64.Decode(h)
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url", ErrMalformedToken)
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header JSON: %v", ErrMalformedToken, err)
	}
	if header.Algorithm == "" || strings.EqualFold(string(header.Algorithm), "none") {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, header.Algorithm)
	}
	if !containsAlg(allowed, header.Algorithm) {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, header.Algorithm)
	}

	key, found, err := keys.Lookup(ctx, header.KeyID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, header.KeyID)
	}
	verifier, err := key.verifierForAlg(header.Algorithm)
	if err != nil {
		return nil, err
	}
	sig, err := b64.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url", ErrMalformedToken)
	}
	if err := verifier.Verify([]byte(h+"."+p), sig); err != nil {
		return nil, ErrInvalidSignature
	}

	payloadJSON, err := b64.Decode(p)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url", ErrMalformedToken)
	}
	var claims Claims[T]
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload JSON: %v", ErrMalformedToken, err)
	}
	if err := validateClaims(payloadJSON, &claims.RegisteredClaims, header, cfg); err != nil {
		return nil, err
	}
	return &claims, nil
}

// ParseInsecure decodes claims WITHOUT verifying the signature or checking
// expiry. Its result MUST NOT drive any authorization decision — read-only
// inspection only (e.g. looking up a session by an expired token's "jti").
func ParseInsecure[T any](token string) (*Claims[T], error) {
	if len(token) > maxTokenBytes {
		return nil, fmt.Errorf("%w: token exceeds %d bytes", ErrMalformedToken, maxTokenBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: need at least a header and a payload", ErrMalformedToken)
	}
	payloadJSON, err := b64.Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url", ErrMalformedToken)
	}
	var claims Claims[T]
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload JSON: %v", ErrMalformedToken, err)
	}
	return &claims, nil
}

type parseConfig struct {
	allowedAlgs    []Algorithm
	issuer         string
	audience       string
	requiredType   string
	now            func() time.Time
	leeway         time.Duration
	requiredClaims []string
}

// ParseOption configures Parse.
type ParseOption func(*parseConfig)

// WithAllowedAlgorithms sets the mandatory algorithm allowlist (RFC 8725
// §3.1). "none" and the empty string are never accepted, even if listed.
func WithAllowedAlgorithms(algs ...Algorithm) ParseOption {
	return func(c *parseConfig) { c.allowedAlgs = append(c.allowedAlgs, algs...) }
}

// WithIssuer requires the "iss" claim to equal iss.
func WithIssuer(iss string) ParseOption {
	return func(c *parseConfig) { c.issuer = iss }
}

// WithAudience requires aud to be present in the "aud" claim.
func WithAudience(aud string) ParseOption {
	return func(c *parseConfig) { c.audience = aud }
}

// WithRequiredType requires the JOSE "typ" header to match typ, ignoring an
// optional "application/" prefix and case (RFC 8725 §3.11).
func WithRequiredType(typ string) ParseOption {
	return func(c *parseConfig) { c.requiredType = typ }
}

// WithClock overrides the clock used for every time-based check. A nil
// function is ignored.
func WithClock(now func() time.Time) ParseOption {
	return func(c *parseConfig) {
		if now != nil {
			c.now = now
		}
	}
}

// WithLeeway allows d of clock skew on "exp" and "nbf" checks (default 0).
func WithLeeway(d time.Duration) ParseOption {
	return func(c *parseConfig) { c.leeway = d }
}

// WithRequiredClaims requires each named claim to be present in the payload.
func WithRequiredClaims(names ...string) ParseOption {
	return func(c *parseConfig) { c.requiredClaims = append(c.requiredClaims, names...) }
}

func validateClaims(raw []byte, rc *RegisteredClaims, header Header, cfg parseConfig) error {
	now := cfg.now()
	if rc.ExpiresAt != nil && !now.Add(-cfg.leeway).Before(rc.ExpiresAt.Time) {
		return ErrExpired
	}
	if rc.NotBefore != nil && now.Add(cfg.leeway).Before(rc.NotBefore.Time) {
		return ErrNotYetValid
	}
	if cfg.issuer != "" && rc.Issuer != cfg.issuer {
		return ErrIssuerMismatch
	}
	if cfg.audience != "" && !rc.Audience.Has(cfg.audience) {
		return ErrAudienceMismatch
	}
	if cfg.requiredType != "" && !typeMatches(header.Type, cfg.requiredType) {
		return ErrTypeMismatch
	}
	if len(cfg.requiredClaims) > 0 {
		present := map[string]json.RawMessage{}
		if err := json.Unmarshal(raw, &present); err != nil {
			return fmt.Errorf("%w: payload JSON: %v", ErrMalformedToken, err)
		}
		for _, name := range cfg.requiredClaims {
			if _, ok := present[name]; !ok {
				return fmt.Errorf("%w: %q", ErrMissingClaim, name)
			}
		}
	}
	return nil
}

// typeMatches compares JOSE "typ" values, ignoring an optional
// "application/" media-type prefix and ASCII case (RFC 8725 §3.11).
func typeMatches(got, want string) bool {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[i+1:]
		}
		return strings.ToLower(s)
	}
	return norm(got) == norm(want)
}

// split3 splits s into exactly three '.'-separated segments.
func split3(s string) (a, b, c string, ok bool) {
	i := strings.IndexByte(s, '.')
	if i < 0 {
		return "", "", "", false
	}
	j := strings.IndexByte(s[i+1:], '.')
	if j < 0 {
		return "", "", "", false
	}
	j += i + 1
	if strings.IndexByte(s[j+1:], '.') >= 0 {
		return "", "", "", false
	}
	return s[:i], s[i+1 : j], s[j+1:], true
}

// withoutNone drops empty and "none" entries from an allowlist (spec §4.2).
func withoutNone(algs []Algorithm) []Algorithm {
	out := make([]Algorithm, 0, len(algs))
	for _, a := range algs {
		if a == "" || strings.EqualFold(string(a), "none") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func containsAlg(algs []Algorithm, want Algorithm) bool {
	for _, a := range algs {
		if a == want {
			return true
		}
	}
	return false
}
