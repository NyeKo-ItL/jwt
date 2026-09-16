package jwt

import (
	"bytes"
	"errors"
	"fmt"

	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

// Untrusted JSON — JOSE headers, claim sets, JWKs and JWKS documents — is
// decoded with encoding/json/v2 defaults rather than encoding/json:
//
//   - member names match struct tags exactly (RFC 7515 §4 and RFC 7519 §4
//     names are case-sensitive; v1 would let "EXP" fill "exp");
//   - duplicate member names are rejected (allowed by RFC 7515 §4 and
//     RFC 7519 §4, which permit either rejecting or last-wins, and it
//     removes parser-differential ambiguity);
//   - invalid UTF-8 is rejected (RFC 8259 §8.1).
//
// Encoding stays on encoding/json so emitted tokens are byte-for-byte
// unchanged.

// errNotObject reports a JSON value that must be an object but is not.
var errNotObject = errors.New("not a JSON object")

// decodeStrict decodes data into v with the strict rules above.
func decodeStrict(data []byte, v any) error {
	return jsonv2.Unmarshal(data, v)
}

// decodeObject is decodeStrict for inputs that MUST be a JSON object: a JWS
// or JWE header (RFC 7515 §4, RFC 7516 §4) or a JWT Claims Set (RFC 7519
// §7.2 step 10). A JSON null — which v2 would silently decode as a zero
// value — is rejected along with every other non-object.
func decodeObject(data []byte, v any) error {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errNotObject
	}

	return jsonv2.Unmarshal(data, v)
}

// registeredHeaderNames are the Header Parameter names defined by RFC 7515
// §4.1, RFC 7516 §4.1 and RFC 7518 §4.6.1/§4.7.1/§4.8.1. RFC 7515 §4.1.11
// forbids listing them in "crit".
var registeredHeaderNames = map[string]bool{
	"alg": true, "jku": true, "jwk": true, "kid": true, "x5u": true, "x5c": true,
	"x5t": true, "x5t#S256": true, "typ": true, "cty": true, "crit": true,
	"enc": true, "zip": true,
	"epk": true, "apu": true, "apv": true, "iv": true, "tag": true, "p2s": true, "p2c": true,
}

// checkCritical enforces RFC 7515 §4.1.11 (and RFC 7516 §4.1.13 for JWE).
// This library implements no header extension, so the set of extensions it
// "understands and processes" is empty: any "crit" member at all makes the
// token invalid. The error still distinguishes the malformed cases the RFC
// calls out (empty list, registered names, names absent from the header) to
// ease debugging.
func checkCritical(headerJSON []byte) error {
	var members map[string]jsontext.Value
	if err := decodeObject(headerJSON, &members); err != nil {
		return fmt.Errorf("%w: header JSON: %w", ErrMalformedToken, err)
	}

	raw, present := members["crit"]
	if !present {
		return nil
	}

	var names []string
	if err := decodeStrict(raw, &names); err != nil || names == nil {
		return fmt.Errorf("%w: \"crit\" must be an array of strings", ErrUnsupportedCritical)
	}

	if len(names) == 0 {
		return fmt.Errorf("%w: \"crit\" must not be empty", ErrUnsupportedCritical)
	}

	for _, name := range names {
		switch {
		case registeredHeaderNames[name]:
			return fmt.Errorf("%w: %q is a registered header parameter and must not be listed", ErrUnsupportedCritical, name)
		case members[name] == nil:
			return fmt.Errorf("%w: %q is listed but absent from the header", ErrUnsupportedCritical, name)
		}
	}

	return fmt.Errorf("%w: %q", ErrUnsupportedCritical, names)
}
