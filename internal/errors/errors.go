// Package errors contains sentinel values shared by internal implementations
// and the public jwt package.
package errors

import "errors"

// Sentinel errors shared by internal packages and re-exported by jwt.
var (
	ErrInvalidSignature     = errors.New("jwt: invalid signature")
	ErrWeakKey              = errors.New("jwt: key does not meet minimum size")
	ErrUnsupportedAlgorithm = errors.New("jwt: unsupported algorithm")
	ErrKeyTypeMismatch      = errors.New("jwt: key type does not match algorithm")
	ErrMalformedKey         = errors.New("jwt: malformed key material")
)
