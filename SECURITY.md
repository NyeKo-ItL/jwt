# Security

This document restates the security requirements the library enforces
itself (spec §4). It is kept in sync with the code.

## Enforced invariants

1. **Mandatory algorithm allowlist on every `Parse` / decrypt path.** There is
   no "accept whatever the header says" mode. `Parse` returns
   `ErrNoAllowedAlgorithms` when `WithAllowedAlgorithms` supplies no usable
   algorithm. Each JWE `Decrypter` is pinned to the algorithms its constructor
   named; a token header cannot select anything else.
2. **`alg: none` (and any `enc`-less JWE construction) is unrepresentable** in
   either direction. It has no constant and no built-in implementation, and the
   allowlist check rejects it independently of any custom `Signer` / `Verifier`.
3. **Curated signing, permissive verification.** Built-in signers cover only
   the best-practice algorithm per key family (HS256/384/512, PS256/384/512,
   ES256/384/512, EdDSA). Verification additionally covers RS256/384/512
   because major external IdPs issue those. Both sides are open to caller
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
   verification key. They are parsed for inspection only (RFC 8725 §3.9–3.10).
9. **`KeyProvider` and `RevocationStore` take a `context.Context`** so
   network-backed implementations can bound their own work.
10. **Anti-confusion at resolution time.** When `Parse` resolves a key, the
    key's own type must match the header `alg` family before a `Verifier` is
    built — an RSA key can never satisfy an `HS256` header.
11. **No panics on malformed input.** Every public parsing / decryption
    function returns `error`; fuzz targets cover `Parse`, `DecryptClaims` and
    `ParseKeySet`.
12. **The clock is injectable** (`WithClock`) for every time-based check.

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainer
listed in `go.mod`. Please do not file public issues for suspected
vulnerabilities.
