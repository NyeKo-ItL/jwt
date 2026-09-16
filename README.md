# jwt

[![Go Reference](https://pkg.go.dev/badge/github.com/NyeKo-ItL/jwt.svg)](https://pkg.go.dev/github.com/NyeKo-ItL/jwt)
[![Latest release](https://img.shields.io/github/v/release/NyeKo-ItL/jwt?display_name=tag&sort=semver)](https://github.com/NyeKo-ItL/jwt/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/NyeKo-ItL/jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/NyeKo-ItL/jwt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/NyeKo-ItL/jwt/graph/badge.svg?token=9IQF77HVZA)](https://codecov.io/gh/NyeKo-ItL/jwt)
[![Scheduled fuzzing](https://github.com/NyeKo-ItL/jwt/actions/workflows/fuzz.yml/badge.svg)](https://github.com/NyeKo-ItL/jwt/actions/workflows/fuzz.yml)
[![Release](https://github.com/NyeKo-ItL/jwt/actions/workflows/release.yml/badge.svg)](https://github.com/NyeKo-ItL/jwt/actions/workflows/release.yml)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/NyeKo-ItL/jwt/badge)](https://securityscorecards.dev/viewer/?uri=github.com/NyeKo-ItL/jwt)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14616/badge)](https://www.bestpractices.dev/projects/14616)
[![CodeQL](https://github.com/NyeKo-ItL/jwt/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/NyeKo-ItL/jwt/actions/workflows/github-code-scanning/codeql)
[![Security scans](https://github.com/NyeKo-ItL/jwt/actions/workflows/security.yml/badge.svg)](https://github.com/NyeKo-ItL/jwt/actions/workflows/security.yml)
[![Dependabot Updates](https://github.com/NyeKo-ItL/jwt/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/NyeKo-ItL/jwt/actions/workflows/dependabot/dependabot-updates)

A single-package JWT / JOSE library for Go with secure defaults: JWS signing
and verification, JWE encryption, JWK / JWKS handling with pluggable key
resolution, OpenID Connect and provider claim sets, the RFC 9068 access-token
profile, opaque tokens, revocation, and an RFC 6750 HTTP bearer adapter.

- **One import path, no third-party runtime dependencies.** Standard library only.
- **Hard to misuse.** Algorithm allowlists are mandatory, `alg: none` cannot be
  expressed, audience is enforced, `crit` is honored, and untrusted JSON and
  base64url are decoded strictly.
- **Checked against the standards.** RFC test vectors, interoperability tests
  against `golang-jwt/jwt/v5` and `go-jose/go-jose/v4`, continuous fuzzing, and a
  requirement-by-requirement [compliance matrix](COMPLIANCE.md).

> **Status: pre-1.0.** The API may still change between minor versions; every
> change is listed in the [CHANGELOG](CHANGELOG.md). Requires **Go 1.27** or later.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [Reusable options](#reusable-options)
  - [OAuth 2.0 access tokens (RFC 9068)](#oauth-20-access-tokens-rfc-9068)
  - [OpenID Connect ID tokens over JWKS](#openid-connect-id-tokens-over-jwks)
  - [Encrypted tokens (JWE)](#encrypted-tokens-jwe)
  - [HTTP middleware (RFC 6750)](#http-middleware-rfc-6750)
  - [Publishing a JWKS](#publishing-a-jwks)
  - [Keys, opaque tokens and revocation](#keys-opaque-tokens-and-revocation)
  - [Errors](#errors)
- [Supported algorithms](#supported-algorithms)
- [Security model](#security-model)
- [Standards](#standards)
- [Project](#project)

## Install

```sh
go get github.com/NyeKo-ItL/jwt
```

## Quick start

A claims value is any struct that marshals to a JSON object. Embed
`jwt.RegisteredClaims` to get `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`
and `cnf`, and give every other field an exact `json` tag. Member names are
matched case-sensitively.

```go
type MyClaims struct {
    jwt.RegisteredClaims
    Role string `json:"role,omitempty"`
}

// Issue
signer, _ := jwt.NewEd25519Signer(priv, "key-1") // kid is optional
token, _ := jwt.Sign(MyClaims{
    RegisteredClaims: jwt.RegisteredClaims{
        Issuer:    "https://auth.example.com",
        Audience:  jwt.Audience{"https://api.example.com"},
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
    },
    Role: "admin",
}, signer)

// Verify
keys := jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(pub, "key-1"))

var claims MyClaims
err := jwt.Parse(ctx, token, &claims, keys,
    jwt.WithAllowedAlgorithms(jwt.Ed25519), // mandatory
    jwt.WithIssuer("https://auth.example.com"),
    jwt.WithAudience("https://api.example.com"),
)
```

`Parse` always checks the signature, `exp` and `nbf`. It rejects a token that
carries an `aud` claim unless `WithAudience` names one of its values
([RFC 7519 §4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3)).

`jwt.ParseInsecure` decodes a payload **without verifying anything**. Use it
only to inspect a token you will not trust, for example to look up a session by
the `jti` of an expired token.

## Usage

Every snippet below is also a compiled, tested example in
[`example_test.go`](example_test.go), shown on
[pkg.go.dev](https://pkg.go.dev/github.com/NyeKo-ItL/jwt#pkg-examples). Runnable
programs live in [`examples/`](examples).

### Reusable options

Declare a policy once as `jwt.ParseOptions` and combine it with per-call `With*`
options. Options apply left to right; the allowlists and required claims merge.

```go
var apiOpts = jwt.ParseOptions{
    AllowedAlgorithms: []jwt.Algorithm{jwt.Ed25519},
    Issuer:            "https://auth.example.com",
}

err := jwt.Parse(ctx, token, &claims, keys, apiOpts, jwt.WithAudience("orders"))
```

| Option | Effect |
|---|---|
| `WithAllowedAlgorithms(...)` | **Required.** Accepted JWS `alg` values; `none` is never accepted |
| `WithIssuer(iss)` | `iss` must equal `iss` |
| `WithAudience(aud)` | `aud` must contain `aud`; a token without `aud` is rejected |
| `WithoutAudienceCheck()` | Accept a token whose `aud` names someone else — only for components that are not the recipient |
| `WithRequiredType(typ)` | `typ` header must match, e.g. `jwt.AccessTokenType` ([RFC 8725 §3.11](https://www.rfc-editor.org/rfc/rfc8725#section-3.11)) |
| `WithRequiredClaims(names...)` | Each named claim must be present |
| `WithLeeway(d)` | Clock-skew allowance for `exp` / `nbf` (default 0) |
| `WithClock(now)` | Time source for all time checks |
| `WithAllowedKeyAlgorithms(...)`, `WithAllowedContentAlgorithms(...)` | **Required for `DecryptClaims`.** JWE `alg` / `enc` allowlists |
| `MiddlewareOptions{Realm, OnError}` | `Middleware` only |

### OAuth 2.0 access tokens (RFC 9068)

```go
// Authorization server: typ MUST be "at+jwt"
token, _ := jwt.Sign(jwt.AccessTokenClaims{
    RegisteredClaims: jwt.RegisteredClaims{
        Issuer: iss, Subject: userID, Audience: jwt.Audience{resource},
        IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
    },
    ClientID: clientID,
    Scope:    "orders:read",
}, signer, jwt.WithType(jwt.AccessTokenType))

// Resource server: all RFC 9068 §4 checks
var at jwt.AccessTokenClaims
err := jwt.Parse(ctx, token, &at, keys,
    jwt.WithAllowedAlgorithms(jwt.ES256),
    jwt.WithRequiredType(jwt.AccessTokenType),
    jwt.WithIssuer(iss),
    jwt.WithAudience(resource),
)
if err == nil {
    err = jwt.ValidateAccessTokenClaims(at) // iss, exp, aud, sub, client_id, iat present
}
```

### OpenID Connect ID tokens over JWKS

```go
uri, err := jwt.DiscoverJWKSURI(ctx, "https://accounts.google.com", nil)
if err != nil { /* errors.Is(err, jwt.ErrKeyFetch) */ }
keys := jwt.NewKeyFetcher(uri)

var idt jwt.GoogleIDToken // also OktaIDToken, EntraIDToken, or your own struct
err = jwt.Parse(ctx, rawIDToken, &idt, keys,
    jwt.WithAllowedAlgorithms(jwt.RS256),
    jwt.WithIssuer("https://accounts.google.com"),
    jwt.WithAudience(clientID),
    jwt.WithRequiredClaims("sub", "iat"),
)

// Relying-party checks that depend on your login flow (OIDC Core §3.1.3.7):
if idt.Nonce != nonceFromSession { /* reject */ }
```

- **`DiscoverJWKSURI`** follows OpenID Connect Discovery 1.0: the issuer must be
  `https`, the document's `issuer` must equal it exactly, and there is no
  fallback URL.
- **`KeyFetcher`** is HTTPS-only (every redirect included) and size-capped.
  Concurrent lookups share one request, and attempts are rate-limited even when
  they fail. It keeps serving the last good keys through an outage, and caps
  `Cache-Control: max-age` (`WithMaxCacheDuration`, default 24 h).
- **Identifying users:** use `sub` (or Entra's `oid` + `tid`), never `email`.

### Encrypted tokens (JWE)

```go
enc, _ := jwt.NewECDHESEncrypter(&recipient.PublicKey, jwt.ECDHESA256KW, jwt.A256GCM, "enc-1")
compact, _ := jwt.EncryptClaims(claims, enc)

dec, _ := jwt.NewECDHESDecrypter(recipient, "enc-1")
var out MyClaims
err := jwt.DecryptClaims(ctx, compact, &out, dec,
    jwt.WithAllowedKeyAlgorithms(jwt.ECDHESA256KW), // mandatory
    jwt.WithAllowedContentAlgorithms(jwt.A256GCM),  // mandatory
)
```

Every decryption failure returns the single `jwt.ErrDecryptionFailed`, and no
plaintext is exposed before the AEAD tag verifies. Compression (`zip`) is
refused.

### HTTP middleware (RFC 6750)

```go
h := jwt.Middleware(keys,
    jwt.WithAllowedAlgorithms(jwt.ES256),
    jwt.WithAudience("https://api.example.com"),
    jwt.MiddlewareOptions{
        Realm:   "api",
        OnError: func(r *http.Request, err error) { slog.WarnContext(r.Context(), "auth failed", "err", err) },
    },
)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    var claims MyClaims
    if err := jwt.ClaimsFromContext(r.Context(), &claims); err != nil { /* ... */ }
    if claims.Role != "admin" {
        jwt.WriteInsufficientScope(w, "api", "admin") // 403
        return
    }
}))
```

| Failure | Response |
|---|---|
| No or unparsable `Authorization: Bearer` | `401`, `WWW-Authenticate: Bearer realm="api"` |
| Malformed token | `400`, `error="invalid_request"` |
| Expired, not yet valid, bad signature, wrong issuer/audience, … | `401`, `error="invalid_token"` |
| JWKS unreachable, request context ended | `503`, no challenge |
| Misconfiguration or KeyProvider backend failure | `500`, no challenge |

Responses contain fixed text only. The full error, which may include internal
hostnames, goes to `OnError`.

### Publishing a JWKS

```go
key := jwt.FromECDSAPublicKey(&priv.PublicKey, "2026-09")
key.Use, key.Alg = "sig", string(jwt.ES256) // one key, one algorithm (RFC 8725 §3.1)

set := jwt.NewKeySet(key)
http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
    w.Header().Set("Content-Type", "application/jwk-set+json")
    _ = json.NewEncoder(w).Encode(set)
})
```

Symmetric (`oct`) keys refuse to marshal (`jwt.ErrOctNotServable`), so a
secret cannot end up in a public key set. A key's `use`, `key_ops` and `alg`
are honored when verifying.

### Keys, opaque tokens and revocation

- **Key material:** parsers for explicit, already-decoded encodings, with no
  file I/O and no format guessing: `ParsePKCS8PrivateKey`,
  `ParsePKCS1PrivateKey`, `ParseSEC1ECPrivateKey`, `ParsePKIXPublicKey`,
  `ParseEd25519PrivateKeySeed`, `ParseOpenSSHPrivateKey`, … Key generation is
  out of scope; use `crypto/*`.
- **Thumbprints:** `Thumbprint(key)` / `ThumbprintBytes(kty, raw)`
  ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)), e.g. for `cnf.jkt`
  ([RFC 7800](https://www.rfc-editor.org/rfc/rfc7800)).
- **Opaque tokens:** `NewOpaqueToken()` returns a random credential plus the
  SHA-256 hash you store; `Equal(storedHash, raw)` compares in constant time.
- **Refresh rotation:** `TokenFamily` and `RotationResult` model reuse
  detection; storage is yours (see
  [`examples/refresh_rotation`](examples/refresh_rotation)).
- **Revocation:** the `RevocationStore` interface (by `jti`, key thumbprint or
  token family) with an in-memory, single-process `NewMemoryRevocationStore`.
  `Parse` does not consult it; check it after parsing.
- **Testing:** [`jwttest`](jwttest) provides fakes and conformance suites for
  your own `KeyProvider` / `RevocationStore` implementations.

### Errors

Every error wraps a sentinel usable with `errors.Is`:

| Sentinel | Meaning |
|---|---|
| `ErrMalformedToken` | Not a well-formed token (segments, base64url, JSON, size) |
| `ErrInvalidSignature` | Signature or MAC does not verify |
| `ErrExpired`, `ErrNotYetValid` | `exp` / `nbf` |
| `ErrIssuerMismatch`, `ErrAudienceMismatch`, `ErrTypeMismatch`, `ErrMissingClaim` | Claim or header policy |
| `ErrAlgorithmNotAllowed` | `alg` / `enc` outside the allowlist, or key family mismatch |
| `ErrKeyNotFound`, `ErrKeyUsage` | No key for `kid`; key's `use` / `key_ops` / `alg` forbid it |
| `ErrUnsupportedCritical` | Token carries a `crit` header |
| `ErrDecryptionFailed` | Any JWE decryption failure |
| `ErrKeyFetch` | JWKS or discovery fetch failed (infrastructure, not the token) |
| `ErrNoAllowedAlgorithms` | Missing mandatory allowlist (configuration) |
| `ErrWeakKey`, `ErrMalformedKey`, `ErrKeyTypeMismatch`, `ErrUnsupportedAlgorithm`, `ErrOctNotServable` | Key or constructor problems |

## Supported algorithms

| | Sign / encrypt | Verify / decrypt |
|---|---|---|
| **JWS** | `HS256` `HS384` `HS512`, `PS256` `PS384` `PS512`, `ES256` `ES384` `ES512`, `Ed25519` | the same, plus `RS256` `RS384` `RS512` and the deprecated `EdDSA` (only when allowlisted) |
| **JWE `alg`** | `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A256KW`, `A256KW`, `dir` | same |
| **JWE `enc`** | `A128GCM`, `A192GCM`, `A256GCM` | same |
| **JWK `kty`** | `RSA` (≥ 2048 bits), `EC` (P-256/384/521), `OKP` (Ed25519), `oct` | same |

- **Not provided:** `none`, `RSA1_5`, `RSA-OAEP` (SHA-1), AES-CBC-HMAC,
  `A128KW`/`A192KW`, PBES2, Ed448/X25519, and JSON serialization. The reasons
  are in [COMPLIANCE.md](COMPLIANCE.md).
- **Custom algorithms:** `Signer`, `Verifier`, `Encrypter`, `Decrypter` and
  `KeyProvider` are plain interfaces, so you can plug in e.g. a KMS signer.
  Allowlists still apply to custom implementations.
- **`Ed25519` naming:** tokens are signed with the `Ed25519` identifier from
  [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864), which replaces `EdDSA`.
  Verifiers that predate RFC 9864, such as `golang-jwt/jwt/v5`, need a
  one-line alias; see [`interop/jws_test.go`](interop/jws_test.go).

## Security model

The library enforces the invariants listed in [SECURITY.md](SECURITY.md).
Highlights:

- **Algorithms:** mandatory allowlists (JWS and JWE); `none` is unrepresentable.
  A key only verifies its own family and its own `alg`/`use`, so RSA cannot be
  confused with HMAC.
- **Untrusted header parameters:** `jku`, `x5u`, `jwk` and `x5c` are never
  dereferenced or trusted, and any `crit` header is rejected.
- **Strict decoding:** canonical base64url; `encoding/json/v2` for headers,
  claims and JWKs (exact member names, no duplicates, valid UTF-8); `NumericDate`
  only as JSON numbers; 1 MiB token limit.
- **Claim checks:** `exp`, `nbf` and `aud` are always enforced; the clock is
  injectable.
- **Secrets:** constant-time comparisons; minimum key sizes (HMAC ≥ hash size,
  RSA ≥ 2048 bits).
- **Decryption:** JWE decryption fails closed with one generic error.
- **Remote keys:** JWKS fetching is HTTPS-only, bounded and rate-limited;
  discovery validates the issuer.

**Still your responsibility:**
- TLS for your own endpoints.
- `nonce` and `azp` checks for OIDC logins.
- Scope and role authorization.
- `jti` replay or revocation checks via `RevocationStore`.
- Key generation, storage and rotation.
- Never using `ParseInsecure` output for authorization.

**Reporting a vulnerability:** use a
[private security advisory](https://github.com/NyeKo-ItL/jwt/security/advisories/new).
Do not open a public issue.

## Standards

| Standard | Coverage |
|---|---|
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) JWS | Compact serialization, full header, `crit` |
| [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) JWE | Compact serialization, AEAD algorithms |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) JWK | Keys and key sets, `use` / `key_ops` / `alg` |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) JWA | Algorithms above; canonical key encodings |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) JWT | Registered claims and validation |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK Thumbprint | Any hash, SHA-256 default |
| [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) Proof-of-Possession | `cnf` with `jwk` / `jkt` |
| [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) CFRG curves | Ed25519 keys and signatures |
| [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) Fully-specified algorithms | `Ed25519`; `EdDSA` deprecated |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) JWT BCP | All §3 practices (some opt-in) |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) Bearer tokens | Header method, challenges, error codes |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens | Claims, `at+jwt`, validation |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) / [Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | ID-token claims, JWKS discovery |

The per-requirement status — implemented, opt-in, not implemented, and the few
deliberate deviations with their reasons — is in **[COMPLIANCE.md](COMPLIANCE.md)**.
A weekly workflow watches these standards for errata, updates and registry
changes.

## Project

| Document | Purpose |
|---|---|
| [pkg.go.dev](https://pkg.go.dev/github.com/NyeKo-ItL/jwt) | API reference with examples |
| [COMPLIANCE.md](COMPLIANCE.md) | Standards traceability matrix |
| [SECURITY.md](SECURITY.md) | Enforced security invariants and vulnerability reporting |
| [CHANGELOG.md](CHANGELOG.md) | Release notes, including breaking changes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and contribution rules |
| [spec.md](spec.md) | Original design specification and rationale |
| [examples/](examples) | Runnable programs |
| [testdata/README.md](testdata/README.md) | Provenance of test vectors and fixtures |

**Quality gates** (CI):
- `go test -race` with RFC known-answer vectors.
- Interoperability tests ([`interop/`](interop)).
- Coverage ≥ 85%.
- `golangci-lint`, including doc-comment checks.
- `govulncheck`, CodeQL and OpenSSF Scorecard.
- Scheduled fuzzing of `Parse`, `DecryptClaims` and `ParseKeySet`.
- From v1.0.0: an `apidiff` gate against breaking API changes.

**Versioning:** [Semantic Versioning](https://semver.org/). Before v1.0.0,
minor versions may contain breaking changes, always listed in the changelog.

## License

MIT — see [LICENSE](LICENSE).
