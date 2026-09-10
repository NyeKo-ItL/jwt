// Package jwt is a single-package JWT/JOSE library.
//
// It covers JWS signing and verification (HMAC, RSA-PSS sign / PKCS#1 v1.5
// verify, ECDSA, Ed25519), JWE encryption and decryption (RSA-OAEP-256,
// ECDH-ES(+A256KW), A256KW, dir with AES-GCM), the RFC 7519 claim model, the
// full RFC 7515 JOSE header, JWK / JWKS handling with pluggable key
// resolution (KeyProvider, KeySet, KeyFetcher), RFC 7638 thumbprints, OIDC
// standard and provider claim sets, the RFC 9068 access-token profile,
// opaque-token utilities, revocation (RevocationStore), per-encoding key
// material parsers, and a thin RFC 6750 bearer adapter.
//
// Verification is mandatory-allowlist by construction: Parse and every
// Decrypter reject any algorithm the caller did not permit, and alg:none is
// never representable. See spec.md for the full design and RFC matrix.
package jwt
