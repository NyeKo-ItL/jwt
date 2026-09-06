// Package b64 provides the base64url (RFC 4648 §5, no padding) encoding used
// throughout JOSE compact serialization. It is internal so it can never
// become an accidental part of the public API surface (spec §7).
package b64

import "encoding/base64"

// Encode returns the base64url encoding of b without padding (RFC 7515 §2).
func Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decode decodes a base64url string that MUST NOT carry padding (RFC 7515
// §2). Padding characters, whitespace, or bytes outside the base64url
// alphabet produce an error.
func Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
