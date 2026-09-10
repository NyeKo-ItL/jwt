# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); the project follows
[Semantic Versioning](https://semver.org/) from `v0.1.0` onward. While on
`v0.x` the public API may still change between minor versions.

## [Unreleased]

## [0.1.0] - 2026-09-10

First public release. Single package, zero third-party runtime dependencies,
Go 1.27+.

### Added

- **JWS.** `Sign` / `Parse` / `ParseInsecure` with a mandatory algorithm
  allowlist (RFC 8725 §3.1), `alg: none` unrepresentable in either direction,
  and a resolution-time anti-confusion check. Built-in `Signer` / `Verifier`
  constructors for HMAC (HS256/384/512), RSA-PSS (PS256/384/512) signing,
  RSA PKCS#1 v1.5 (RS256/384/512) verify-only, ECDSA (ES256/384/512) and
  Ed25519. `Signer` / `Verifier` are open interfaces for HSM/KMS or other
  algorithms.
- **JWE.** `EncryptClaims` / `DecryptClaims`, the `Encrypter` / `Decrypter`
  interfaces, AES-GCM content encryption, and key management for
  `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A256KW`, `A256KW` and `dir` — with a
  dependency-free RFC 3394 AES Key Wrap and RFC 7518 §4.6 Concat KDF.
  Decryption fails closed with a single generic `ErrDecryptionFailed`.
- **Claim model.** `RegisteredClaims` (embed it in your own struct;
  `Sign`/`Parse` are generic over that struct, no wrapper type), `Audience`,
  `NumericDate`, `Confirmation` (RFC 7800 `cnf`), and the full RFC 7515 §4.1
  `Header`.
- **OIDC.** `StandardClaims`, `Address`, `GoogleClaims` / `OktaClaims` /
  `EntraClaims`, and the ready-made `GoogleIDToken` / `OktaIDToken` /
  `EntraIDToken` structs.
- **RFC 9068.** `AccessTokenClaims`, `AccessTokenType`,
  `ValidateAccessTokenClaims`; emit `typ: at+jwt` with
  `Sign(..., jwt.WithType(jwt.AccessTokenType))`.
- **JWK / JWKS.** `Key`, `ParseKey`, `From{RSA,ECDSA,Ed25519}PublicKey`,
  `FromHMACSecret`, `Thumbprint` / `ThumbprintBytes` (RFC 7638), `KeySet` /
  `ParseKeySet`, and `KeyFetcher` / `DiscoverJWKSURI` (HTTPS-only,
  size-capped, `Cache-Control` aware). `oct` keys refuse to marshal into a
  servable JWKS document.
- **Key resolution & storage** are injectable: `KeyProvider`
  (`StaticKeyProvider`, `MapKeyProvider`, `KeySet`, `KeyFetcher`) and
  `RevocationStore` (`NewMemoryRevocationStore`), both taking a
  `context.Context`.
- **Opaque tokens.** `OpaqueToken`, `NewOpaqueToken`, `DeriveOpaqueToken`,
  `Hash`, constant-time `Equal`, plus `TokenFamily` / `RotationResult`
  shapes for refresh rotation with reuse detection.
- **HTTP (RFC 6750).** `BearerToken`, `Middleware`, `ClaimsFromContext`,
  `WriteChallenge`.
- **Key material parsers** (explicit per-encoding, no auto-detection):
  PKCS#8, PKCS#1, SEC1, PKIX, raw Ed25519 seed / expanded / public, and a
  dependency-free unencrypted OpenSSH parser.
- **Options.** `Parse` / `DecryptClaims` / `Middleware` take `ParseOption`
  (functional `With*`) or a reusable `ParseOptions{}` struct — they combine
  in one call. `Sign` takes `SignOption` / `SignOptions{}` the same way.
- **Testing helpers.** `jwttest` sub-package: `FakeKeyProvider`,
  `FakeRevocationStore`, `NewSigningPair`, and the
  `RunKeyProviderConformance` / `RunRevocationStoreConformance` suites.
- Runnable `examples/` (basic HMAC, ID-token over JWKS, JWE round trip,
  refresh rotation, HTTP middleware) and a separate `interop/` module that
  cross-checks every algorithm against `golang-jwt/jwt/v5` and
  `go-jose/go-jose/v4` in both directions.

[Unreleased]: https://github.com/NyeKo-ItL/jwt/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NyeKo-ItL/jwt/releases/tag/v0.1.0
