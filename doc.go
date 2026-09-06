// Package jwt is a single-package JWT/JOSE library. This first slice covers
// the JWS core: the RFC 7519 claim model, the JOSE header, and signing /
// verification across the HMAC, RSA (RSA-PSS built-in sign; PKCS#1 v1.5
// verify-only), ECDSA and Ed25519 algorithm families, together with the
// mandatory-allowlist Parse path. See spec.md for the full design.
package jwt
