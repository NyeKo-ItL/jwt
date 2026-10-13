# Migration to v1.0.0

This guide covers behavior and API changes from `v0.2.0` to the planned stable
release.

## Toolchain

- Upgrade to Go **1.27.2** or later. Go 1.27.1 contains reachable standard
  library vulnerabilities fixed in 1.27.2.

## Parsing and verification

- `Parse`, `ParseInsecure`, `DecryptClaims`, and `ClaimsFromContext` now replace
  destinations atomically. Code must not rely on merge-style decoding.
- `ParseInsecure` requires exactly three compact-JWS segments.
- `WithRequiredClaims` rejects both absent and JSON `null` values.
- Payload and signature base64url are validated before `KeyProvider` I/O.
- A JWK without `alg` is rejected when multiple compatible algorithms are
  allowlisted. Bind keys with `Key.Alg` or use one algorithm per policy.
- Use `WithVerifierProvider` for HSM/KMS or custom verification. The returned
  verifier must match the protected `alg` and `kid`.
- Provider callback errors now wrap `ErrKeyProvider` or
  `ErrVerifierProvider` while retaining the original error for `errors.Is`.

## Profiles

- RFC 9068 access tokens must contain `jti`; set `RegisteredClaims.ID` before
  calling `ValidateAccessTokenClaims`.
- For ID Tokens, parse into `IDTokenClaims`, call `ValidateIDTokenClaims`, then
  call `ValidateIDTokenForContext` with the client ID and flow state needed for
  audience, `azp`, nonce, `at_hash`, and `c_hash` checks.
- `Sign` and `EncryptClaims` reject values that do not marshal to a JSON object.
- `NumericDate` now preserves fractional seconds when marshaled.

## JWE

- Public-key JWE encryption does **not** authenticate the sender. Replace direct
  asymmetric `EncryptClaims`/`DecryptClaims` authorization flows with a signed
  inner JWS and `EncryptNestedJWT`/`DecryptNestedJWT`.
- Built-in JWE encrypters accept `WithJWEType` and `WithJWEContentType` through
  `EncryptJWE`, `EncryptClaims`, and `EncryptNestedJWT`.
- A non-empty decrypter `kid` must match a non-empty protected-header `kid`.
- Invalid AES-KW lengths, equal `apu`/`apv`, and private `epk` parameters are
  rejected before plaintext is returned.

## Keys and JWKS

- RSA keys must be between 2048 and 8192 bits.
- ECDSA signatures are deterministic RFC 6979; signature bytes for the same
  payload and key are now stable and will differ from prior randomized output.
- `KeySet`, `StaticKeyProvider`, and `MapKeyProvider` deep-copy key material.
- Untrusted JWKS parsing is bounded. `ParseKeySet` is strict;
  `ParseKeySetPermissive` follows RFC 7517 §5 by returning valid understood keys
  plus diagnostics for ignored members.
- `ThumbprintBytes(KeyTypeOKP, raw)` requires an exact 32-byte Ed25519 key.

## Remote keys

- `KeyFetcher` applies a safe default URL policy that rejects direct local,
  private-looking, and IP-literal hosts. Private deployments must provide an
  explicit allowlist with `WithURLPolicy`.
- Stale fallback is bounded by `WithMaxStaleDuration`; `0` disables fallback.
- `Cache-Control: no-cache`, `no-store`, and case-insensitive `max-age` are
  honored. JWKS response size and key count are bounded.

## Opaque tokens and revocation

- Prefer `HashOpaqueToken`, `VerifyOpaqueTokenHash`, and
  `OpaqueTokenFromRaw`. `Hash`, `Equal`, and `DeriveOpaqueToken` are deprecated.
- `OpaqueToken` redacts its raw credential from standard Go formatting.
- Empty revocation IDs are rejected. Use
  `NewMemoryRevocationStoreWithCapacity` when an explicit memory bound is
  required.
