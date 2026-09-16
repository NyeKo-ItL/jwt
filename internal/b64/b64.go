// Package b64 provides the base64url (RFC 4648 §5, no padding) encoding used
// throughout JOSE compact serialization. It is internal so it can never
// become an accidental part of the public API surface (spec §7).
package b64

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Encode returns the base64url encoding of b without padding (RFC 7515 §2).
func Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// errNewline reports a CR or LF, which encoding/base64 would otherwise skip.
var errNewline = errors.New("b64: line breaks are not allowed")

// Decode decodes a base64url string that MUST NOT carry padding (RFC 7515
// §2). Decoding is canonical: padding, whitespace (including the CR and LF
// that encoding/base64 silently skips), bytes outside the base64url alphabet,
// and non-zero trailing bits (RFC 4648 §3.5) all produce an error, so each
// byte string has exactly one accepted encoding and tokens are not malleable.
func Decode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errNewline
	}

	return base64.RawURLEncoding.Strict().DecodeString(s)
}
