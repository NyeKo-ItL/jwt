# Security

This document restates the security requirements the library enforces
itself (spec §4). It is kept in sync with the code.

## Enforced invariants

1. **Mandatory algorithm allowlist on every `Parse` / decrypt path.** There is
   no "accept whatever the header says" mode. `Parse` returns
   `ErrNoAllowedAlgorithms` when `WithAllowedAlgorithms` supplies no usable
   algorithm; `DecryptClaims` does the same unless both
   `WithAllowedKeyAlgorithms` ("alg") and `WithAllowedContentAlgorithms`
   ("enc") are given. Both checks run on the header before any caller-supplied
   `Verifier` / `Decrypter` is involved.
2. **`alg: none` (and any `enc`-less JWE construction) is unrepresentable** in
   either direction. It has no constant and no built-in implementation, and the
   allowlist check rejects it independently of any custom `Signer` / `Verifier`.
3. **Curated signing, permissive verification.** Built-in signers cover only
   the best-practice algorithm per key family (HS256/384/512, PS256/384/512,
   ES256/384/512, Ed25519 per RFC 9864). Verification additionally covers
   RS256/384/512 because major external IdPs issue those, and the deprecated
   polymorphic `EdDSA` identifier when explicitly allowlisted. Both sides are open to caller
   extension via the `Signer` / `Verifier` interfaces.
4. **Verified vs. unverified parsing are distinct functions.** `ParseInsecure`
   never checks the signature or expiry and MUST NOT drive an authorization
   decision.
5. **Constant-time comparisons** for every secret/hash comparison
   (`crypto/hmac.Equal`, `crypto/subtle`).
6. **Minimum key sizes** enforced at construction: HMAC keys shorter than the
   hash output are rejected; RSA keys below 2048 bits are rejected (JWS and
   JWE).
7. **JWE decryption fails closed.** The AEAD tag is verified before any
   plaintext is returned; every failure collapses to the single generic
   `ErrDecryptionFailed`.
8. **`jku`, `x5u`, `jwk`, `x5c` are never dereferenced** or trusted to select a
   verification key. They are parsed for inspection only (RFC 8725 §3.10).
9. **`KeyProvider` and `RevocationStore` take a `context.Context`** so
   network-backed implementations can bound their own work.
10. **Anti-confusion at resolution time.** When `Parse` resolves a key, the
    key's own type must match the header `alg` family before a `Verifier` is
    built — an RSA key can never satisfy an `HS256` header.
11. **No panics on malformed input.** Every public parsing / decryption
    function returns `error`; fuzz targets cover `Parse`, `DecryptClaims` and
    `ParseKeySet`.
12. **The clock is injectable** (`WithClock`) for every time-based check.
13. **Strict, unambiguous decoding.** Base64url must be canonical (no padding,
    line breaks or non-zero trailing bits), so a token has one valid string
    form. Headers, claim sets and JWKs are decoded with `encoding/json/v2`
    defaults: exact member names, duplicates and invalid UTF-8 rejected.
    `NumericDate` accepts only JSON numbers. Tokens are capped at 1 MiB.
14. **`crit` is enforced** (RFC 7515 §4.1.11, RFC 7516 §4.1.13): no header
    extension is implemented, so any `crit` is rejected before key lookup.
    JWE `zip` is refused.
15. **Audience is enforced by default** (RFC 7519 §4.1.3): a token carrying
    `aud` is rejected unless `WithAudience` names one of its values;
    `WithoutAudienceCheck` is an explicit opt-out.
16. **Key usage and canonical keys.** A JWK's `use`, `key_ops` and `alg`
    restrict what it verifies; non-canonical RSA/EC/OKP encodings are rejected
    so each key has exactly one RFC 7638 thumbprint.
17. **Hardened remote key retrieval.** `KeyFetcher` and `DiscoverJWKSURI` are
    HTTPS-only on every redirect hop, size-capped, single-flight and
    rate-limited (including failures); `max-age` is capped; discovery requires
    the returned `issuer` to match exactly.
18. **No internal detail in HTTP responses.** `WriteChallenge` / `Middleware`
    send fixed texts; infrastructure failures are 5xx, not `invalid_token`.

Known-answer RFC vectors, interoperability tests and the requirement-level
status of every standard are documented in [COMPLIANCE.md](COMPLIANCE.md).

## Supported versions

The project is pre-1.0: security fixes land on the latest minor release only.
Upgrade to the newest `v0.x` to receive them.

## Reporting a vulnerability

Open a [private security advisory](https://github.com/NyeKo-ItL/jwt/security/advisories/new)
on the repository. Please do not file public issues for suspected
vulnerabilities.
