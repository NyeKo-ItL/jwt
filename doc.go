// Package jwt is a single-package JWT/JOSE library with secure defaults.
//
// It covers JWS signing and verification (HMAC, RSA-PSS, ECDSA and Ed25519;
// RSA PKCS#1 v1.5 verification), JWE encryption and decryption
// (RSA-OAEP-256, ECDH-ES, ECDH-ES+A256KW, A256KW and dir with AES-GCM), the
// RFC 7519 claim model, the full RFC 7515 JOSE header, JWK / JWKS handling
// with pluggable key resolution (KeyProvider, KeySet, KeyFetcher), RFC 7638
// thumbprints, OpenID Connect standard and provider claim sets, the RFC 9068
// access-token profile, opaque-token utilities, revocation
// (RevocationStore), per-encoding key material parsers, and an RFC 6750
// bearer adapter.
//
// # Secure defaults
//
// Parse requires WithAllowedAlgorithms and DecryptClaims requires
// WithAllowedKeyAlgorithms and WithAllowedContentAlgorithms (RFC 8725 §3.1);
// "none" is never representable. "exp", "nbf" and "aud" are always enforced
// (RFC 7519 §4.1.3–4.1.5), a "crit" header is rejected (RFC 7515 §4.1.11),
// and untrusted input is decoded strictly: canonical base64url, and
// encoding/json/v2 with exact member names, no duplicates and valid UTF-8.
// Header parameters such as "jku", "x5u" and "jwk" are never dereferenced
// (RFC 8725 §3.10). A JWK's "use", "key_ops" and "alg" restrict what it can
// verify.
//
// # Documentation
//
// README.md has a usage guide, COMPLIANCE.md maps each RFC requirement to its
// implementation and tests, SECURITY.md lists the enforced invariants, and
// spec.md records the original design.
package jwt
