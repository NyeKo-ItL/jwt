package jwt

import (
	"bytes"
	"encoding/json"
	"math"
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
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*a = s
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*a = Audience{s}
	return nil
}

// Has reports whether v is one of the audience values.
func (a Audience) Has(v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
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
	return []byte(strconv.FormatInt(n.Time.Unix(), 10)), nil
}

// UnmarshalJSON accepts a JSON number (integer or fractional seconds), the
// same number quoted as a string, or null.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return err
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

// Claims combines RegisteredClaims with an application-defined payload,
// flattened into the same JSON object on the wire. A registered claim always
// wins over a same-named field in the custom payload.
type Claims[T any] struct {
	RegisteredClaims
	Custom T
}

// MarshalJSON flattens RegisteredClaims and Custom into one JSON object.
func (c Claims[T]) MarshalJSON() ([]byte, error) {
	reg, err := json.Marshal(c.RegisteredClaims)
	if err != nil {
		return nil, err
	}
	custom, err := json.Marshal(c.Custom)
	if err != nil {
		return nil, err
	}
	merged := map[string]json.RawMessage{}
	if err := mergeObject(merged, custom); err != nil {
		return nil, err
	}
	if err := mergeObject(merged, reg); err != nil {
		return nil, err
	}
	return json.Marshal(merged)
}

// UnmarshalJSON fills RegisteredClaims and Custom from the same JSON object.
func (c *Claims[T]) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &c.RegisteredClaims); err != nil {
		return err
	}
	return json.Unmarshal(b, &c.Custom)
}

// mergeObject unmarshals a JSON object into dst, overwriting existing keys.
// A null or empty input is a no-op; a non-object input is an error.
func mergeObject(dst map[string]json.RawMessage, obj []byte) error {
	if len(obj) == 0 || string(bytes.TrimSpace(obj)) == "null" {
		return nil
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(obj, &m); err != nil {
		return err
	}
	for k, v := range m {
		dst[k] = v
	}
	return nil
}
