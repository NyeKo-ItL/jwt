# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow [Semantic Versioning](https://semver.org/) from `v0.1.0` onward.

## [Unreleased]

### Added

- `Sign` accepts variadic `SignOption`: `WithType` (override or omit `typ`,
  e.g. `AccessTokenType` for RFC 9068) and `WithContentType`.
- `jwttest` sub-package: `FakeKeyProvider`, `FakeRevocationStore`,
  `NewSigningPair`, and the `RunKeyProviderConformance` /
  `RunRevocationStoreConformance` shared test suites.
- `examples/`: basic_hmac, verify_idtoken, jwe_roundtrip, refresh_rotation,
  http_middleware.
- JWS core: `Sign`, `Parse`, `ParseInsecure`, the `Signer` / `Verifier`
  interfaces and built-in constructors for HMAC (HS256/384/512), RSA-PSS
  (PS256/384/512) signing, RSA PKCS#1 v1.5 (RS256/384/512) verification,
  ECDSA (ES256/384/512) and Ed25519. Mandatory algorithm allowlist,
  `alg: none` unrepresentable, resolution-time anti-confusion check,
  injectable clock and leeway.
- Claim model: `RegisteredClaims`, generic `Claims[T]`, `Audience`,
  `NumericDate`, `Confirmation`, and the full RFC 7515 §4.1 `Header`.
- OIDC claims: `StandardClaims`, `Address`, `GoogleClaims`, `OktaClaims`,
  `EntraClaims`, and the generic `IDToken[Provider]` with an `Extra`
  catch-all.
- RFC 9068: `AccessTokenClaims`, `AccessTokenType`,
  `ValidateAccessTokenClaims`.
- JWE: `EncryptClaims` / `DecryptClaims`, the `Encrypter` / `Decrypter`
  interfaces, AES-GCM content encryption, and key management for
  `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A256KW`, `A256KW` and `dir`
  (dependency-free RFC 3394 key wrap and RFC 7518 §4.6 Concat KDF).
- JWK / JWKS: `Key`, `ParseKey`, `From*PublicKey`, `FromHMACSecret`,
  `Thumbprint` / `ThumbprintBytes` (RFC 7638), `KeySet` / `ParseKeySet`,
  and `KeyFetcher` / `DiscoverJWKSURI` (HTTPS-only, size-capped,
  `Cache-Control` aware).
- Opaque tokens: `OpaqueToken`, `NewOpaqueToken`, `DeriveOpaqueToken`,
  `Hash`, `Equal`, plus `TokenFamily` / `RotationResult` shapes.
- Revocation: `RevocationStore` interface and `NewMemoryRevocationStore`.
- HTTP: `BearerToken`, generic `Middleware`, `ClaimsFromContext`,
  `WriteChallenge` (RFC 6750).
- Key material parsers: PKCS#8, PKCS#1, SEC1, PKIX, raw Ed25519
  seed/expanded/public, and a dependency-free unencrypted OpenSSH parser.

### Changed

- **Removed `Claims[T]`.** `Sign` / `Parse` / `ParseInsecure` /
  `EncryptClaims` / `DecryptClaims` / `Middleware` / `ClaimsFromContext` are
  now generic over `C any` — pass and receive your own claims struct
  directly (embed `RegisteredClaims` to flatten the registered members, or
  use `RegisteredClaims` alone). No more `Custom` field, no custom-marshaler
  merge.
- `Sign` options trimmed to `WithType` and `WithContentType`
  (`WithHeaderParam` removed).
- `MapKeyProvider` now resolves an empty requested kid to the sole key,
  matching `KeySet` and the `KeyProvider` contract.
- `NewTokenFamily` no longer panics on CSPRNG failure (impossible since
  Go 1.24); the package now contains no `panic` in non-test code.

### Fixed

- JWE `ECDH-ES+A256KW`: the Concat KDF `AlgorithmID` used `"A256KW"` instead
  of the `"alg"` header value (`"ECDH-ES+A256KW"`) required by RFC 7518
  §4.6.2. Round-tripping within this library worked, but tokens were not
  interoperable with other JOSE implementations. Now verified against
  `go-jose/go-jose/v4` in both directions.
