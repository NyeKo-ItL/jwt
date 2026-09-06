# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow [Semantic Versioning](https://semver.org/) from `v0.1.0` onward.

## [Unreleased]

### Added

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
