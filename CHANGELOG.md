# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); the project follows
[Semantic Versioning](https://semver.org/) from `v0.1.0` onward. While on
`v0.x` the public API may still change between minor versions.

## [UNRELEASED]

### Security

- **`KeyFetcher` never leaves HTTPS.** Redirects to any non-`https` URL are
  refused (previously the configured URL was checked but redirects were
  followed to `http://`, letting a JWKS be loaded over plaintext). A client
  passed to `WithHTTPClient` is copied, never mutated, and its own
  `CheckRedirect` still applies after the HTTPS check.
- **`KeyFetcher` no longer amplifies traffic.** Concurrent lookups share one
  in-flight request, and network attempts — including failed ones — are
  rate-limited to one per `WithMinRefreshInterval`. Previously every request
  carrying an unknown `kid` during an outage caused its own upstream fetch.
- **`KeyFetcher` serves the last good keys during an outage** instead of
  failing every token.
- **`Cache-Control: max-age` is capped** at 24 hours by default
  (`WithMaxCacheDuration`), so a removed key cannot stay trusted for long.
- **`DiscoverJWKSURI` validates the discovery document** per OpenID Connect
  Discovery 1.0: the issuer must be `https` with no query or fragment, the
  returned `issuer` must equal the requested one exactly (§4.3), and
  `jwks_uri` must be `https`. It no longer silently falls back to
  `<issuer>/.well-known/jwks.json` on errors, and a nil client now gets a
  30-second timeout instead of `http.DefaultClient`.

- **`crit` header enforced** (RFC 7515 §4.1.11). It was parsed but ignored, so
  tokens relying on extensions the library does not implement (e.g. RFC 7797
  `b64`) were accepted. Any `crit` now yields `ErrUnsupportedCritical`, before
  the key lookup.
- **Strict JSON decoding of untrusted input** via `encoding/json/v2`: header
  and claim names are case-sensitive (`"ALG"` / `"EXP"` no longer act as
  `alg` / `exp`), duplicate member names and invalid UTF-8 are rejected, and
  headers and claim sets must be JSON objects. Applies to `Parse`,
  `ParseInsecure`, `DecryptClaims`, `ClaimsFromContext`, `ParseKey`,
  `ParseKeySet` and discovery documents.
- **Canonical base64url.** Non-zero trailing bits, CR and LF are rejected, so a
  valid token can no longer be re-encoded into a different string that still
  verifies (which defeated deny-lists and replay caches keyed on the token).
- **`typ` comparison follows RFC 7515 §4.1.9**: only an `application/` prefix
  may be omitted, so `typ: "evil/at+jwt"` no longer satisfies
  `WithRequiredType("at+jwt")`.
- **`NumericDate` accepts only JSON numbers in years 1–9999.** Quoted strings,
  `"NaN"`/`"Inf"` and huge values — whose integer conversion differed between
  CPU architectures — are rejected.

- **Audience enforced per RFC 7519 §4.1.3.** A token with an `aud` claim was
  accepted when no `WithAudience` was configured, allowing a token issued for
  another service by the same issuer to be replayed. It is now rejected with
  `ErrAudienceMismatch`; `WithoutAudienceCheck()` /
  `ParseOptions.SkipAudienceCheck` opt out explicitly.
- **JWK `use`, `key_ops` and `alg` are honored** when verifying (RFC 7517
  §4.2–4.4, RFC 8725 §3.1): a key published for encryption, or for a different
  algorithm, no longer verifies signatures (`ErrKeyUsage`).
- **One encoding per key.** `ParseKey` / `ParseKeySet` / header `jwk` reject RSA
  integers with leading zero octets, EC coordinates that are not exactly the
  curve size and non-32-byte Ed25519 keys, which previously let a single key
  have several RFC 7638 thumbprints (weakening `cnf.jkt` binding and
  thumbprint-keyed revocation). Duplicate `key_ops` values and `key_ops`
  inconsistent with `use` are rejected.

- **`DecryptClaims` enforces a mandatory `alg`/`enc` allowlist** (spec §4.1,
  RFC 8725 §3.1), checked on the protected header before the `Decrypter` runs.
  Previously it consulted no allowlist at all, contrary to `SECURITY.md`.
- **JWE input is size-capped** at 1 MiB, like `Parse` (spec §4.11).
- **JWE `zip` is refused and `crit` enforced** (RFC 7516 §4.1.3, §4.1.13);
  `alg` and `enc` must both be present.

- **HTTP error responses no longer leak internals.** `WriteChallenge` /
  `Middleware` put `err.Error()` into `error_description`, exposing internal
  hostnames, IPs and backend errors (e.g. a failing JWKS URL). Responses now
  carry fixed text only; full detail goes to the new
  `MiddlewareOptions.OnError` hook.
- **Infrastructure failures are no longer reported as bad tokens.** JWKS/
  context failures answer 503 and misconfiguration or backend errors 500,
  without a `WWW-Authenticate` challenge, instead of 401 `invalid_token`.
- **`BearerToken` enforces RFC 6750 §2.1** `b64token` syntax, accepts `1*SP`
  after the scheme, and rejects requests with several `Authorization` headers.

### Added

- `ErrKeyFetch`, wrapped by every remote key-fetch or discovery failure.
- `WithMaxCacheDuration` fetcher option.
- `ErrUnsupportedCritical`.
- `WithoutAudienceCheck`, `ParseOptions.SkipAudienceCheck`.
- `ErrKeyUsage`; `Key.KeyOps` (parsed and serialized as `key_ops`).
- `WithAllowedKeyAlgorithms`, `WithAllowedContentAlgorithms`,
  `ParseOptions.AllowedKeyAlgorithms`, `ParseOptions.AllowedContentAlgorithms`.
- `Ed25519` algorithm identifier (RFC 9864 §2.2).
- `Bool` OIDC boolean claim type; `EntraClaims.IdentityProvider` (`idp`),
  `SessionID` (`sid`), `TokenID` (`uti`).
- `MiddlewareOptions` (`Realm`, `OnError`) and `WriteInsufficientScope`
  (RFC 6750 §3.1 `insufficient_scope`).
- `WithRequiredType` now also applies to the JWE protected header in
  `DecryptClaims`.

### Deprecated

- `EdDSA`, deprecated by RFC 9864 §4.1.2 (IANA JOSE registry: "Deprecated").
  It is still verified over Ed25519 keys when explicitly allowlisted; nothing
  emits it any more.

### Fixed

- **Okta's documented ID token failed to decode**: `OktaClaims.Version` was a
  `string` but Okta emits `"ver": 1` (a number). It is now an `int`.
- **Providers sending `"email_verified": "true"`** (Google's documented
  example, Amazon Cognito) failed to decode into `*bool`. `EmailVerified` and
  `PhoneNumberVerified` are now `*Bool`, which accepts `true`/`false` and
  `"true"`/`"false"` and marshals as a JSON boolean.

- **ECDH-ES `apu` / `apv` are honored** as PartyUInfo / PartyVInfo in the Concat
  KDF (RFC 7518 §4.6.1.2–3). They were ignored, so tokens from producers that
  set them — including the RFC 7518 Appendix C example, now a test vector —
  failed to decrypt.

### Documentation

- **`COMPLIANCE.md`**: requirement-by-requirement traceability for RFC 7515,
  7516, 7517, 7518, 7519, 7638, 7800, 8037, 8725, 9864, 6750, 9068 and OpenID
  Connect Core / Discovery, with code and test references, plus the
  deliberate deviations (no `none`, no CBC-HMAC JWE, whole-set rejection of a
  malformed JWKS member) and their reasons.
- **README rewritten**: usage guide for every feature, option and error
  reference, supported-algorithm table, security model (including the checks
  that remain the caller's), standards summary and project documents.
  Snippets are backed by compiled, output-checked `Example` functions.
- **Doc comments** on every exported identifier, with RFC section references
  at each enforcement point; `revive` (`exported`, `package-comments`,
  `blank-imports`) and `godoclint` now run in CI.
- `SECURITY.md` lists the new invariants and the supported-versions policy;
  `CONTRIBUTING.md` and the PR template require tests first and
  `COMPLIANCE.md` updates.

### Testing

- **Known-answer vectors** (spec §7.2.1) in `testdata/vectors/jose.json`,
  transcribed from the RFCs: RFC 7515 Appendix A.1–A.4 (HS256, RS256, ES256,
  ES512, verified and — for HMAC — re-signed byte-for-byte, JWT vectors also
  through `Parse`), A.5 (`alg: none` rejected), RFC 7520 §4.1–4.4 (RS256,
  PS384, ES512 with a zero-padded P-521 coordinate, HS256) and §5.6
  (`dir` + A128GCM). Inline: RFC 3394 §4.3/§4.6 AES Key Wrap, RFC 8037 A.3/A.4,
  RFC 7518 Appendix C, RFC 7638 §3.1.
- **Provider fixtures** (spec §7.2.8) in `testdata/idtoken_fixtures/`: the
  documented Google and Okta ID-token payloads verbatim, and an Entra v2.0
  payload built from its claims reference, each signed and run through `Parse`
  with OIDC Core §2 required claims, plus a member-name round trip.


- `DiscoverJWKSURI` returns an error where it used to return a guessed
  `/.well-known/jwks.json` URL.
- `KeyFetcher` errors now wrap `ErrKeyFetch` (malformed JWKS documents wrap
  both `ErrKeyFetch` and `ErrMalformedKey`).
- Claim structs passed to `Parse` / `ParseInsecure` / `DecryptClaims` /
  `ClaimsFromContext` are decoded with `encoding/json/v2`: `json` tag names
  must match the token's member names exactly (v1 matched case-insensitively).
- `NumericDate` no longer decodes from a JSON string.
- `Parse` / `DecryptClaims` / `Middleware` reject tokens carrying `aud` unless
  `WithAudience` matches or `WithoutAudienceCheck` is given.
- `DecryptClaims` returns `ErrNoAllowedAlgorithms` unless both
  `WithAllowedKeyAlgorithms` and `WithAllowedContentAlgorithms` are given, and
  `ErrAlgorithmNotAllowed` for a header outside them.
- **`NewEd25519Signer` emits `alg: "Ed25519"`** instead of `"EdDSA"`
  (RFC 9864), and the Ed25519 verifiers report `Ed25519`. Allowlists must name
  `Ed25519`; `EdDSA` no longer matches tokens produced by this library.
  Verifiers that predate RFC 9864 (e.g. golang-jwt v5, go-jose v4) need to
  register the identifier — see the interop tests. A JWK `alg` of either value
  serves both identifiers (RFC 9864 §5).
- `StandardClaims.EmailVerified` / `PhoneNumberVerified` are `*Bool` (was
  `*bool`); `OktaClaims.Version` is `int` (was `string`).
- `WriteChallenge` status codes and `error_description` texts changed (see
  its documentation); 5xx responses carry no challenge.
- A `Key` whose `use` / `key_ops` / `alg` forbid the operation no longer
  verifies; `Key.PublicKey` no longer left-pads short EC coordinates.

## [0.1.3] - 2026-09-13

This release keeps the exported API unchanged while reducing the public package's
implementation surface and making development and CI checks more representative.

### Changed

- **Internal structure.** Moved signing algorithms, key parsing, encoding,
  byte-handling, internal errors, and option helpers into `internal/` packages.
  The public API and its behavior remain unchanged; consumers cannot import
  these implementation packages through the `jwt` module.
- **Public package clarity.** Kept only API-facing code at the package root and
  moved implementation-specific tests alongside the internal packages.
- **Readable formatting.** Added the local whitespace rule to development
  linting so functions and logical blocks are separated consistently. The rule
  remains advisory in CI; the standard lint and formatter checks stay blocking.

### Testing and CI

- **Coverage.** Added direct tests for internal key parsing and signing
  algorithm failure paths, and enabled coverage measurement for the root,
  `internal/...`, and `jwttest` packages. CI now requires at least 85% aggregate
  coverage; Codecov uses 85% project coverage with a 1% threshold and 90% patch
  coverage.
- **API contracts.** Added tests that pin the public error and interface
  contracts while allowing implementation details to move into `internal/`.
- **Development commands.** Added a Makefile with standard `fmt`, `lint`,
  `test`, `test-race`, `coverage`, `vet`, `check`, and cleanup targets.

## [0.1.2] - 2026-09-13

### Changed

- **Reproducible security tooling.** Pinned the `govulncheck` and `apidiff`
  tool versions used by CI and release verification instead of depending on
  moving `latest` versions.
- **Security reporting.** Linked directly to the repository's private security
  advisory flow and clarified that vulnerabilities must not be reported in
  public issues.

## [0.1.1] - 2026-09-13

### Added

- **CI and release automation.** Added multi-platform Go 1.27 testing on Linux,
  macOS, and Windows, scheduled fuzzing, security scans, Codecov reporting,
  and tag-driven GitHub release automation.
- **Repository maintenance.** Added issue and pull-request templates,
  CODEOWNERS, Dependabot configuration, workflow status badges, and release
  configuration suitable for a library module.

### Changed

- **Library releases.** Disabled binary artifacts in GoReleaser; releases now
  publish the Go module release without treating the library as an executable.

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

[0.1.4]: https://github.com/NyeKo-ItL/jwt/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/NyeKo-ItL/jwt/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/NyeKo-ItL/jwt/releases/tag/v0.1.2
[0.1.1]: https://github.com/NyeKo-ItL/jwt/releases/tag/v0.1.1
[0.1.0]: https://github.com/NyeKo-ItL/jwt/releases/tag/v0.1.0
