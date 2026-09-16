package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"time"
)

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

// MarshalJSON emits the value as integer seconds since the Unix epoch.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(n.Unix(), 10)), nil
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
	Issuer       string        `json:"iss,omitempty"`
	Subject      string        `json:"sub,omitempty"`
	Audience     Audience      `json:"aud,omitempty"`
	ExpiresAt    *NumericDate  `json:"exp,omitempty"`
	NotBefore    *NumericDate  `json:"nbf,omitempty"`
	IssuedAt     *NumericDate  `json:"iat,omitempty"`
	ID           string        `json:"jti,omitempty"`
	Confirmation *Confirmation `json:"cnf,omitempty"`
}
