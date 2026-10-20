package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// maxTokenBytes bounds the input accepted by Parse / ParseInsecure so a
// malformed or hostile token cannot force unbounded work (spec §4.11).
const maxTokenBytes = 1 << 20 // 1 MiB

// DefaultType is the "typ" header value Sign stamps on a token unless
// WithType overrides it: the RFC 7519 §5.1 recommended media type, also
// satisfying the explicit-typing guidance of RFC 8725 §3.11. For an RFC 9068
// access token pass WithType(AccessTokenType).
const DefaultType = "JWT"

var (
	// ErrInvalidClaims reports that a value supplied for signing is not a JWT
	// Claims Set JSON object. Marshal errors keep their original identity and
	// are not replaced by this sentinel.
	ErrInvalidClaims = errors.New("jwt: invalid Claims Set")
	// ErrInvalidDestination reports a nil destination passed to Parse,
	// ParseInsecure or ClaimsFromContext. Destinations are otherwise updated
	// atomically: any error leaves the caller's value unchanged.
	ErrInvalidDestination = errors.New("jwt: nil claims destination")
)

// SignOption customizes the JOSE header Sign emits; it never affects "alg".
// Both the functional options (WithType, WithContentType) and a SignOptions
// struct satisfy it and combine in one call, applied left to right:
//
//	base := jwt.SignOptions{Type: jwt.AccessTokenType}
//	tok, _ := jwt.Sign(claims, signer, base, jwt.WithContentType("example"))
type SignOption interface {
	applySign(c *signConfig) // unexported: options come from this package only
}

type signConfig struct {
	typ         string
	contentType string
}

type signOptionFunc func(*signConfig)

func (f signOptionFunc) applySign(c *signConfig) { f(c) }

// SignOptions is the reusable, declarative form of the header settings. A
// zero Type keeps DefaultType (use WithType("") to omit "typ" entirely); a
// zero ContentType leaves "cty" unset.
type SignOptions struct {
	Type        string // "typ" header (RFC 7515 §4.1.9); zero keeps DefaultType
	ContentType string // "cty" header (RFC 7515 §4.1.10); zero omits it
}

func (o SignOptions) applySign(c *signConfig) {
	if o.Type != "" {
		c.typ = o.Type
	}

	if o.ContentType != "" {
		c.contentType = o.ContentType
	}
}

// WithType overrides the "typ" header parameter (RFC 7515 §4.1.9). The
// default is DefaultType; pass "" to omit "typ" entirely, or
// AccessTokenType for the RFC 9068 profile.
func WithType(typ string) SignOption {
	return signOptionFunc(func(c *signConfig) { c.typ = typ })
}

// WithContentType sets the "cty" header parameter (RFC 7515 §4.1.10), used
// mainly to mark a nested JWT payload.
func WithContentType(cty string) SignOption {
	return signOptionFunc(func(c *signConfig) { c.contentType = cty })
}

// Sign JSON-encodes claims — which must marshal to a JSON object — and
// produces a compact JWS (RFC 7515 §7.1). The generated header carries "alg",
// "typ" (DefaultType unless WithType is given), an optional "cty" from
// WithContentType, and — when the signer has one — "kid". Nil options are
// ignored. Errors returned by a custom Signer are wrapped with context while
// retaining their identity for errors.Is/errors.As.
func Sign[C any](claims C, signer Signer, opts ...SignOption) (string, error) {
	if isNilValue(signer) {
		return "", fmt.Errorf("%w: nil signer", ErrUnsupportedAlgorithm)
	}

	alg := signer.Algorithm()
	if alg == "" || strings.EqualFold(string(alg), "none") {
		return "", fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, alg)
	}

	cfg := signConfig{typ: DefaultType}

	for _, o := range opts {
		if isNilValue(o) {
			continue
		}

		o.applySign(&cfg)
	}

	headerJSON, err := json.Marshal(Header{
		Algorithm:   alg,
		Type:        cfg.typ,
		ContentType: cfg.contentType,
		KeyID:       signer.KeyID(),
	})
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	var claimsSet map[string]jsontext.Value
	if err := decodeObject(payloadJSON, &claimsSet); err != nil {
		return "", fmt.Errorf("%w: claims JSON: %w", ErrInvalidClaims, err)
	}

	signingInput := b64.Encode(headerJSON) + "." + b64.Encode(payloadJSON)

	sig, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("jwt: signer callback: %w", err)
	}

	return signingInput + "." + b64.Encode(sig), nil
}

// Parse decodes a compact JWS, verifies its signature with a key resolved
// from keys, validates the registered claims per opts, and unmarshals the
// payload into dst (a pointer to any struct; embed RegisteredClaims to read
// the registered members). dst's type is inferred, so calls carry no
// explicit type argument:
//
//	var claims MyClaims
//	err := jwt.Parse(ctx, token, &claims, keys, jwt.WithAllowedAlgorithms(jwt.Ed25519))
//
// Registered-claim validation runs regardless of what dst models. Decoding is
// atomic: dst is assigned only after complete successful decoding. Nil options
// are ignored. WithAllowedAlgorithms is mandatory (RFC 8725 §3.1); Parse
// returns ErrNoAllowedAlgorithms if no usable algorithm is supplied.
func Parse[C any](ctx context.Context, token string, dst *C, keys KeyProvider, opts ...ParseOption) error {
	if dst == nil {
		return ErrInvalidDestination
	}

	cfg := parseConfig{now: time.Now}

	for _, o := range opts {
		if isNilValue(o) {
			continue
		}

		o.applyParse(&cfg)
	}

	payloadJSON, err := parseVerified(ctx, token, keys, cfg)
	if err != nil {
		return err
	}

	if err := decodeFreshObject(payloadJSON, dst); err != nil {
		return fmt.Errorf("%w: payload JSON: %w", ErrMalformedToken, err)
	}

	return nil
}

// parseVerified runs everything Parse does except the final unmarshal into a
// caller type: it returns the verified, claim-validated payload JSON. The
// order follows RFC 7519 §7.2 and RFC 7515 §5.2, with every check on
// attacker-controlled input done before the KeyProvider is consulted.
func parseVerified(ctx context.Context, token string, keys KeyProvider, cfg parseConfig) ([]byte, error) {
	// RFC 8725 §3.1: an allowlist is mandatory; "none" can never be allowed.
	allowed := withoutNone(cfg.allowedAlgs)
	if len(allowed) == 0 {
		return nil, ErrNoAllowedAlgorithms
	}

	if len(token) > maxTokenBytes {
		return nil, fmt.Errorf("%w: token exceeds %d bytes", ErrMalformedToken, maxTokenBytes)
	}

	// RFC 7519 §7.2 steps 1–2, RFC 7515 §7.1: exactly three segments. A
	// five-segment JWE is not accepted here (RFC 7516 §9).
	h, p, s, ok := split3(token)
	if !ok {
		return nil, fmt.Errorf("%w: expected three '.'-separated segments", ErrMalformedToken)
	}

	// RFC 7515 §5.2 steps 2–3: all three segments use canonical, unpadded
	// base64url. Validate attacker-controlled encodings before invoking either
	// provider so malformed tokens cannot trigger I/O or custom callbacks.
	headerJSON, err := b64.Decode(h)
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url", ErrMalformedToken)
	}

	var header Header
	if err := decodeObject(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header JSON: %w", ErrMalformedToken, err)
	}

	members, err := headerMembers(headerJSON)
	if err != nil {
		return nil, err
	}

	// RFC 7515 §5.2 step 5: every header parameter must be understood.
	if err := checkCritical(members); err != nil {
		return nil, err
	}

	// RFC 7515 §4.1.1 ("alg" is REQUIRED), RFC 8725 §3.1–3.2: reject "none"
	// and anything outside the caller's allowlist.
	if header.Algorithm == "" || strings.EqualFold(string(header.Algorithm), "none") {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, header.Algorithm)
	}

	if !containsAlg(allowed, header.Algorithm) {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, header.Algorithm)
	}

	payloadJSON, err := b64.Decode(p)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url", ErrMalformedToken)
	}

	sig, err := b64.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url", ErrMalformedToken)
	}

	var verifier Verifier
	if !isNilValue(cfg.verifierProvider) {
		verifier, err = lookupVerifier(ctx, cfg.verifierProvider, header)
		if err != nil {
			return nil, err
		}
	} else {
		if isNilValue(keys) {
			return nil, fmt.Errorf("%w: nil KeyProvider", ErrKeyNotFound)
		}

		// Key resolution by "kid" only; "jku", "jwk", "x5u" and "x5c" are
		// never used to find or trust a key (RFC 8725 §3.10, spec §4.8).
		key, found, lookupErr := keys.Lookup(ctx, header.KeyID)
		if lookupErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrKeyProvider, lookupErr)
		}

		if !found {
			return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, header.KeyID)
		}

		if err := requireUnambiguousKeyAlgorithm(key, allowed); err != nil {
			return nil, err
		}

		// Spec §4.10 and RFC 8725 §3.1: the key's type and its own
		// use/key_ops/alg must permit this algorithm, so an RSA key can never
		// satisfy HS256.
		verifier, err = key.verifierForAlg(header.Algorithm)
		if err != nil {
			return nil, err
		}
	}

	// RFC 7515 §5.2 step 8: the signing input is the ASCII of the encoded
	// header and payload exactly as received. Custom verifier errors remain
	// discoverable while every verification rejection is ErrInvalidSignature.
	if err := verifier.Verify([]byte(h+"."+p), sig); err != nil {
		return nil, fmt.Errorf("%w: verifier callback: %w", ErrInvalidSignature, err)
	}

	if cfg.headerOut != nil {
		*cfg.headerOut = header
	}

	if cfg.rawPayload {
		return payloadJSON, nil
	}

	// RFC 7519 §7.2 step 10: the claims set must be a JSON object. A nested
	// JWT ("cty": "JWT", step 8) is not unwrapped, so it fails here.
	var reg RegisteredClaims
	if err := decodeObject(payloadJSON, &reg); err != nil {
		return nil, fmt.Errorf("%w: payload JSON: %w", ErrMalformedToken, err)
	}

	if err := validateClaims(payloadJSON, &reg, header, cfg); err != nil {
		return nil, err
	}

	return payloadJSON, nil
}

// ParseInsecure decodes the payload into dst WITHOUT verifying the signature
// or checking expiry. Its result MUST NOT drive any authorization decision —
// read-only inspection only (e.g. looking up a session by an expired token's
// "jti"). The compact input must still contain exactly three segments.
// Decoding is atomic: dst is assigned only after complete successful decoding.
func ParseInsecure[C any](token string, dst *C) error {
	if dst == nil {
		return ErrInvalidDestination
	}

	if len(token) > maxTokenBytes {
		return fmt.Errorf("%w: token exceeds %d bytes", ErrMalformedToken, maxTokenBytes)
	}

	_, payload, _, ok := split3(token)
	if !ok {
		return fmt.Errorf("%w: expected three '.'-separated segments", ErrMalformedToken)
	}

	payloadJSON, err := b64.Decode(payload)
	if err != nil {
		return fmt.Errorf("%w: payload is not base64url", ErrMalformedToken)
	}

	if err := decodeFreshObject(payloadJSON, dst); err != nil {
		return fmt.Errorf("%w: payload JSON: %w", ErrMalformedToken, err)
	}

	return nil
}

type parseConfig struct {
	allowedAlgs      []Algorithm
	issuer           string
	audience         string
	requiredType     string
	now              func() time.Time
	leeway           time.Duration
	requiredClaims   []string
	skipAudience     bool
	verifierProvider VerifierProvider

	// rawPayload skips the RFC 7519 §7.2 step 10 claims-set checks, for a JWS
	// whose payload is not a JWT (a signed CMW, RFC 9999 §4.2). headerOut, when
	// set, receives the verified header.
	rawPayload bool
	headerOut  *Header

	allowedKeyAlgs     []KeyAlgorithm     // JWE "alg" allowlist (DecryptClaims)
	allowedContentAlgs []ContentAlgorithm // JWE "enc" allowlist (DecryptClaims)

	middleware MiddlewareOptions // Middleware only
}

// ParseOption configures Parse, DecryptClaims and Middleware. Both the
// functional options below (WithIssuer, WithAudience, ...) and a ParseOptions
// struct satisfy it, so a reusable declarative config and per-call overrides
// combine in a single call — options apply left to right, so a later one
// wins:
//
//	base := jwt.ParseOptions{
//		AllowedAlgorithms: []jwt.Algorithm{jwt.RS256, jwt.ES256},
//		Issuer:            "https://accounts.google.com",
//	}
//	err := jwt.Parse(ctx, tok, &claims, keys, base, jwt.WithAudience(clientID))
type ParseOption interface {
	applyParse(c *parseConfig) // unexported: options come from this package only
}

type parseOptionFunc func(*parseConfig)

func (f parseOptionFunc) applyParse(c *parseConfig) { f(c) }

// ParseOptions is the reusable, declarative form of the parse configuration.
// A zero field imposes no constraint (and, for Clock, keeps the default). It
// carries exactly the same settings as the With* options; mix the two freely.
type ParseOptions struct {
	// AllowedAlgorithms is the mandatory algorithm allowlist (RFC 8725 §3.1).
	// It is merged with any WithAllowedAlgorithms in the same call.
	AllowedAlgorithms []Algorithm
	// AllowedKeyAlgorithms and AllowedContentAlgorithms are the mandatory JWE
	// "alg" and "enc" allowlists for DecryptClaims; Parse and Middleware
	// ignore them. They merge with WithAllowedKeyAlgorithms /
	// WithAllowedContentAlgorithms in the same call.
	AllowedKeyAlgorithms     []KeyAlgorithm
	AllowedContentAlgorithms []ContentAlgorithm // see AllowedKeyAlgorithms
	Issuer                   string             // require "iss" to equal this (RFC 7519 §4.1.1)
	Audience                 string             // require this to be present in "aud" (RFC 7519 §4.1.3)
	SkipAudienceCheck        bool               // accept a present "aud" when Audience is empty (see WithoutAudienceCheck)
	RequiredType             string             // require the JOSE "typ" header to match (RFC 8725 §3.11)
	RequiredClaims           []string           // require each named claim to be present and non-null
	Leeway                   time.Duration      // clock-skew allowance on "exp"/"nbf" (default 0)
	Clock                    func() time.Time   // time source for every time-based check (default time.Now)
	VerifierProvider         VerifierProvider   // custom verifier lookup for Parse/Middleware; replaces KeyProvider when non-nil
}

func (o ParseOptions) applyParse(c *parseConfig) {
	c.allowedAlgs = append(c.allowedAlgs, o.AllowedAlgorithms...)
	c.allowedKeyAlgs = append(c.allowedKeyAlgs, o.AllowedKeyAlgorithms...)

	c.allowedContentAlgs = append(c.allowedContentAlgs, o.AllowedContentAlgorithms...)
	if o.Issuer != "" {
		c.issuer = o.Issuer
	}

	if o.Audience != "" {
		c.audience = o.Audience
	}

	if o.RequiredType != "" {
		c.requiredType = o.RequiredType
	}

	c.requiredClaims = append(c.requiredClaims, o.RequiredClaims...)
	if o.SkipAudienceCheck {
		c.skipAudience = true
	}

	if o.Leeway != 0 {
		c.leeway = o.Leeway
	}

	if o.Clock != nil {
		c.now = o.Clock
	}

	if !isNilValue(o.VerifierProvider) {
		c.verifierProvider = o.VerifierProvider
	}
}

// WithAllowedAlgorithms sets the mandatory algorithm allowlist (RFC 8725
// §3.1). "none" and the empty string are never accepted, even if listed.
func WithAllowedAlgorithms(algs ...Algorithm) ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.allowedAlgs = append(c.allowedAlgs, algs...) })
}

// WithAllowedKeyAlgorithms sets the JWE key-management ("alg") allowlist
// that DecryptClaims requires (RFC 8725 §3.1). "none" and the empty string
// are never accepted, even if listed. Parse and Middleware ignore it.
func WithAllowedKeyAlgorithms(algs ...KeyAlgorithm) ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.allowedKeyAlgs = append(c.allowedKeyAlgs, algs...) })
}

// WithAllowedContentAlgorithms sets the JWE content-encryption ("enc")
// allowlist that DecryptClaims requires (RFC 8725 §3.1). "none" and the empty
// string are never accepted, even if listed. Parse and Middleware ignore it.
func WithAllowedContentAlgorithms(encs ...ContentAlgorithm) ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.allowedContentAlgs = append(c.allowedContentAlgs, encs...) })
}

// WithIssuer requires the "iss" claim to equal iss.
func WithIssuer(iss string) ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.issuer = iss })
}

// WithAudience identifies the recipient: aud must be one of the values of
// the "aud" claim (exact, case-sensitive string comparison), and a token
// without "aud" is rejected.
//
// Without WithAudience, a token that carries an "aud" claim is rejected with
// ErrAudienceMismatch, because RFC 7519 §4.1.3 requires a principal that
// cannot identify itself with a value in "aud" to reject the JWT (see also
// RFC 8725 §3.9). Use WithoutAudienceCheck to opt out explicitly.
func WithAudience(aud string) ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.audience = aud })
}

// WithoutAudienceCheck accepts a token carrying an "aud" claim even though no
// WithAudience is configured. It deliberately departs from RFC 7519 §4.1.3
// and should be reserved for components that are not the token's recipient
// (e.g. a gateway that only inspects a token before forwarding it). It has no
// effect when WithAudience is also given: an explicit audience is always
// enforced.
func WithoutAudienceCheck() ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.skipAudience = true })
}

// WithRequiredType requires the JOSE "typ" header — of the JWS for Parse, of
// the JWE protected header for DecryptClaims — to match typ as a media type
// (RFC 8725 §3.11, RFC 7515 §4.1.9).
func WithRequiredType(typ string) ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.requiredType = typ })
}

// WithClock overrides the clock used for every time-based check. A nil
// function is ignored.
func WithClock(now func() time.Time) ParseOption {
	return parseOptionFunc(func(c *parseConfig) {
		if now != nil {
			c.now = now
		}
	})
}

// WithLeeway allows d of clock skew on "exp" and "nbf" checks (default 0).
func WithLeeway(d time.Duration) ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.leeway = d })
}

// WithRequiredClaims requires each named claim to be present and non-null in
// the payload. False, zero, empty strings, and empty arrays remain present.
func WithRequiredClaims(names ...string) ParseOption {
	return parseOptionFunc(func(c *parseConfig) { c.requiredClaims = append(c.requiredClaims, names...) })
}

// WithVerifierProvider makes Parse and Middleware resolve a custom Verifier by
// the protected "alg" and "kid" values instead of using their KeyProvider
// argument. A nil provider is ignored. The mandatory algorithm allowlist and
// returned verifier algorithm/key-ID checks remain enforced.
func WithVerifierProvider(provider VerifierProvider) ParseOption {
	return parseOptionFunc(func(c *parseConfig) {
		if !isNilValue(provider) {
			c.verifierProvider = provider
		}
	})
}

// validateClaims applies the registered-claim rules shared by Parse,
// DecryptClaims and Middleware.
func validateClaims(raw []byte, rc *RegisteredClaims, header Header, cfg parseConfig) error {
	now := cfg.now()

	// RFC 7519 §4.1.4: the current time MUST be before "exp".
	if rc.ExpiresAt != nil && !now.Add(-cfg.leeway).Before(rc.ExpiresAt.Time) {
		return ErrExpired
	}

	// RFC 7519 §4.1.5: the current time MUST be after or equal to "nbf".
	if rc.NotBefore != nil && now.Add(cfg.leeway).Before(rc.NotBefore.Time) {
		return ErrNotYetValid
	}

	// RFC 7519 §4.1.1, RFC 8725 §3.8: exact, case-sensitive issuer match.
	if cfg.issuer != "" && rc.Issuer != cfg.issuer {
		return ErrIssuerMismatch
	}

	switch {
	case cfg.audience != "":
		if !rc.Audience.Has(cfg.audience) {
			return ErrAudienceMismatch
		}
	case rc.Audience != nil && !cfg.skipAudience:
		// RFC 7519 §4.1.3: "aud" is present (even as "" or []) but this
		// principal has not identified itself, so the JWT MUST be rejected.
		return fmt.Errorf("%w: token has an \"aud\" claim but no audience is configured (use WithAudience)", ErrAudienceMismatch)
	}

	if cfg.requiredType != "" && !typeMatches(header.Type, cfg.requiredType) {
		return ErrTypeMismatch
	}

	if len(cfg.requiredClaims) > 0 {
		present := map[string]jsontext.Value{}
		if err := decodeObject(raw, &present); err != nil {
			return fmt.Errorf("%w: payload JSON: %w", ErrMalformedToken, err)
		}

		for _, name := range cfg.requiredClaims {
			raw, ok := present[name]
			if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("%w: %q", ErrMissingClaim, name)
			}
		}
	}

	return nil
}

// typeMatches compares two JOSE "typ" media-type values (RFC 8725 §3.11).
// Per RFC 7515 §4.1.9 a value containing no "/" is treated as if
// "application/" were prepended; any other top-level type is distinct. Media
// types compare case-insensitively (RFC 2045 §5.1). No whitespace is trimmed.
func typeMatches(got, want string) bool {
	norm := func(s string) string {
		if !strings.Contains(s, "/") {
			s = "application/" + s
		}

		return strings.ToLower(s)
	}

	return got != "" && want != "" && norm(got) == norm(want)
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
func withoutNone[A ~string](algs []A) []A {
	out := make([]A, 0, len(algs))
	for _, a := range algs {
		if a == "" || strings.EqualFold(string(a), "none") {
			continue
		}

		out = append(out, a)
	}

	return out
}

func containsAlg(algs []Algorithm, want Algorithm) bool {
	return slices.Contains(algs, want)
}

// decodeFreshObject preserves dst on every decoding failure.
func decodeFreshObject[C any](data []byte, dst *C) error {
	if dst == nil {
		return ErrInvalidDestination
	}

	var fresh C
	if err := decodeObject(data, &fresh); err != nil {
		return err
	}

	*dst = fresh

	return nil
}

func isNilValue(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func lookupVerifier(ctx context.Context, provider VerifierProvider, header Header) (Verifier, error) {
	verifier, found, err := provider.LookupVerifier(ctx, header.Algorithm, header.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerifierProvider, err)
	}

	if !found || isNilValue(verifier) {
		return nil, fmt.Errorf("%w: verifier for alg %q and kid %q", ErrKeyNotFound, header.Algorithm, header.KeyID)
	}

	if !sameAlgorithm(verifier.Algorithm(), header.Algorithm) {
		return nil, fmt.Errorf("%w: verifier is for %q, token uses %q", ErrKeyUsage, verifier.Algorithm(), header.Algorithm)
	}

	if header.KeyID != "" && verifier.KeyID() != header.KeyID {
		return nil, fmt.Errorf("%w: verifier kid is %q, token uses %q", ErrKeyUsage, verifier.KeyID(), header.KeyID)
	}

	return verifier, nil
}

// requireUnambiguousKeyAlgorithm enforces RFC 8725 §3.1 when a JWK does not
// bind itself with "alg". A key may be inferred only when exactly one distinct
// compatible algorithm is allowlisted. Incompatible algorithms do not make the
// key ambiguous, and duplicate allowlist entries count once.
func requireUnambiguousKeyAlgorithm(key Key, allowed []Algorithm) error {
	if key.Alg != "" {
		return nil
	}

	seen := make(map[Algorithm]bool, len(allowed))
	compatible := make([]Algorithm, 0, 2)

	for _, alg := range allowed {
		identity := alg
		if identity == EdDSA {
			identity = Ed25519
		}

		if seen[identity] {
			continue
		}

		seen[identity] = true

		if _, err := key.verifierForAlg(alg); err == nil {
			compatible = append(compatible, alg)
			if len(compatible) > 1 {
				return fmt.Errorf("%w: key %q has no alg and is compatible with allowlisted algorithms %q", ErrKeyUsage, key.Kid, compatible)
			}
		}
	}

	return nil
}
