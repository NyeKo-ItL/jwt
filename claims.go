package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidClaim reports a present claim whose value violates the claim's
// profile syntax or cross-claim constraints. It is distinct from
// ErrMissingClaim; profile validators wrap it with the claim name and detail.
var ErrInvalidClaim = errors.New("jwt: invalid claim value")

// ValidateStringOrURI validates RFC 7519 §2 StringOrURI syntax. Values without
// a colon are arbitrary case-sensitive strings. Values containing a colon must
// be valid RFC 3986 URIs. The function validates only; it never normalizes, so
// callers can continue to compare issuer, subject, and audience values exactly.
func ValidateStringOrURI(value string) error {
	colon := strings.IndexByte(value, ':')
	if colon < 0 {
		return nil
	}

	if colon == 0 || !isAlpha(value[0]) {
		return fmt.Errorf("%w: %q is not a StringOrURI", ErrInvalidClaim, value)
	}

	for i := 1; i < colon; i++ {
		c := value[i]
		if !isAlpha(c) && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return fmt.Errorf("%w: %q is not a StringOrURI", ErrInvalidClaim, value)
		}
	}

	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '%' {
			if i+2 >= len(value) || !isHex(value[i+1]) || !isHex(value[i+2]) {
				return fmt.Errorf("%w: %q is not a StringOrURI", ErrInvalidClaim, value)
			}

			i += 2

			continue
		}

		if !isURIChar(c) {
			return fmt.Errorf("%w: %q is not a StringOrURI", ErrInvalidClaim, value)
		}
	}

	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("%w: %q is not a StringOrURI", ErrInvalidClaim, value)
	}

	return nil
}

func isAlpha(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func isURIChar(c byte) bool {
	if isAlpha(c) || ('0' <= c && c <= '9') {
		return true
	}

	return strings.ContainsRune("-._~:/?#[]@!$&'()*+,;=", rune(c))
}

// Audience is RFC 7519 §4.1.3's audience claim: transparently (de)serialized
// from either a bare JSON string or a JSON array of strings.
type Audience []string

// MarshalJSON emits a single-element audience as a bare string and any other
// length as a JSON array (RFC 7519 §4.1.3).
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}

	return json.Marshal([]string(a))
}

// UnmarshalJSON accepts a bare string, a JSON array of strings, or null.
func (a *Audience) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*a = nil
		return nil
	}

	if b[0] == '[' {
		var s []string
		if err := decodeStrict(b, &s); err != nil {
			return err
		}

		*a = s

		return nil
	}

	var s string
	if err := decodeStrict(b, &s); err != nil {
		return err
	}

	*a = Audience{s}

	return nil
}

// Has reports whether v is one of the audience values.
func (a Audience) Has(v string) bool {
	return slices.Contains(a, v)
}

// NumericDate is RFC 7519 §2's NumericDate (seconds since the Unix epoch),
// exposed as a time.Time.
type NumericDate struct{ time.Time }

// NewNumericDate wraps t as a *NumericDate.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t}
}

// MarshalJSON emits seconds since the Unix epoch as a JSON number, preserving
// nanosecond precision when present. Integer times retain their compact form.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	sec, nsec := n.Unix(), n.Nanosecond()
	if nsec == 0 {
		return []byte(strconv.FormatInt(sec, 10)), nil
	}

	negative := sec < 0

	whole, fraction := sec, nsec
	if negative {
		// time.Time represents -0.5 as sec=-1,nsec=500ms. Convert that floor
		// representation to the conventional decimal spelling "-0.5".
		whole = -(sec + 1)
		fraction = int(time.Second) - nsec
	}

	frac := strings.TrimRight(fmt.Sprintf("%09d", fraction), "0")

	prefix := ""
	if negative {
		prefix = "-"
	}

	return []byte(prefix + strconv.FormatInt(whole, 10) + "." + frac), nil
}

// NumericDate bounds: 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z, the
// range time.Time formats losslessly as RFC 3339.
const (
	minNumericDate = -62135596800
	maxNumericDate = 253402300799
)

// errNumericDateRange reports a NumericDate outside [minNumericDate, maxNumericDate].
var errNumericDateRange = errors.New("jwt: NumericDate out of range")

// UnmarshalJSON accepts only what RFC 7519 §2 defines: a JSON numeric value
// of seconds since the epoch, integer or fractional, or null (leaving the
// value unchanged). Strings — including "NaN" and "Inf" — are rejected, as
// are values outside years 1 to 9999, whose conversion to an integer would
// otherwise be platform-dependent.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}

	var f float64
	if err := decodeStrict(b, &f); err != nil {
		return err
	}

	if math.IsNaN(f) || f < minNumericDate || f > maxNumericDate {
		return errNumericDateRange
	}

	sec, frac := math.Modf(f)
	n.Time = time.Unix(int64(sec), int64(math.Round(frac*1e9))).UTC()

	return nil
}

// Confirmation is the RFC 7800 §3 "cnf" claim, binding a token to a
// proof-of-possession key.
type Confirmation struct {
	JWKThumbprint string `json:"jkt,omitempty"` // RFC 7800 §3.3 + RFC 7638
	JWK           *Key   `json:"jwk,omitempty"` // RFC 7800 §3.2
}

// RegisteredClaims holds every generic claim this library targets from the
// IANA "JSON Web Token Claims" registry: the original seven from RFC 7519
// §4.1 plus "cnf" from RFC 7800.
//
// Embed it in your own claims struct so those members flatten into the same
// JSON object — that struct is what you pass to Sign / EncryptClaims and get
// back from Parse / DecryptClaims:
//
//	type MyClaims struct {
//		jwt.RegisteredClaims
//		Scope string `json:"scope,omitempty"`
//		Role  string `json:"role,omitempty"`
//	}
type RegisteredClaims struct {
	// Issuer is "iss" (RFC 7519 §4.1.1), checked by WithIssuer.
	Issuer string `json:"iss,omitempty"`
	// Subject is "sub" (RFC 7519 §4.1.2).
	Subject string `json:"sub,omitempty"`
	// Audience is "aud" (RFC 7519 §4.1.3). When present, Parse rejects the
	// token unless WithAudience names one of its values.
	Audience Audience `json:"aud,omitempty"`
	// ExpiresAt is "exp" (RFC 7519 §4.1.4), always checked when present.
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	// NotBefore is "nbf" (RFC 7519 §4.1.5), always checked when present.
	NotBefore *NumericDate `json:"nbf,omitempty"`
	// IssuedAt is "iat" (RFC 7519 §4.1.6). Informational; not validated.
	IssuedAt *NumericDate `json:"iat,omitempty"`
	// ID is "jti" (RFC 7519 §4.1.7), e.g. a key for RevocationStore.
	ID string `json:"jti,omitempty"`
	// Confirmation is "cnf" (RFC 7800 §3.1), a proof-of-possession key
	// binding. Its presence is not enforced by Parse; checking the proof is
	// the caller's responsibility.
	Confirmation *Confirmation `json:"cnf,omitempty"`
}
