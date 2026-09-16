# Standards compliance

This document maps the requirements of each standard this library targets to
the code that implements them and the tests that prove it. It is the
reference for "what does `jwt` implement, and what does it deliberately not".

**Legend**

| Mark | Meaning |
|---|---|
| ✅ | Implemented and enforced by the library, with tests |
| 🟡 | Supported, but the caller must opt in or perform the check (the reason is given) |
| ⛔ | Not implemented, by design — the reason is given |
| ⚠️ | Deliberate deviation from a normative statement — the reason is given |

Scope: the library is a JWT/JOSE **library** (sign, verify, encrypt, decrypt,
keys, claim validation, bearer extraction). It is not an OAuth authorization
server nor an OIDC relying-party flow engine (`spec.md` §2.2), so RFC 6749,
RFC 7009, RFC 7591, RFC 7636, RFC 8414, RFC 8707 and RFC 9728 are out of scope.

Test names refer to `*_test.go` in the module root unless a path is given;
`interop/` is a separate module testing against `golang-jwt/jwt/v5` and
`go-jose/go-jose/v4`. Standards status was last checked on **2026-09-16**; the
weekly standards-watch workflow reports later changes.

---

## RFC 7515 — JSON Web Signature (JWS)

| § | Requirement | Status | Implementation · Tests |
|---|---|---|---|
| 2 | Base64url without padding; no line breaks or other characters | ✅ Canonical decoding: padding, CR/LF, non-alphabet and non-zero trailing bits rejected | `internal/b64` · `TestDecodeIsCanonical`, `TestDecodeRejectsLineBreaks`, `TestParseRejectsNonCanonicalBase64` |
| 4 | Header is a JSON object; names are case-sensitive; duplicates rejected or last-wins | ✅ Strict `encoding/json/v2` decoding, duplicates rejected | `strictjson.go` · `TestParseHeaderNamesAreCaseSensitive`, `TestParseRejectsDuplicateMemberNames`, `TestParseRejectsInvalidUTF8` |
| 4.1.1 | `alg` REQUIRED, verified before use | ✅ Mandatory allowlist, `none` unrepresentable | `jwt.go` `parseVerified` · `TestParseRequiresAllowlist`, `TestParseRejectsAlgNone`, `TestParseRejectsAlgNotInAllowlist` |
| 4.1.2–4.1.3, 4.1.5–4.1.8 | `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256` | ✅ Parsed and exposed on `Header`; never fetched or trusted (RFC 8725 §3.10) | `header.go` · `TestHeaderFullRoundTrip` |
| 4.1.4 | `kid` | ✅ Only key-selection input | `keyprovider.go`, `keyset.go` · `TestParseKeyResolution`, `TestKeyProviderConformance` |
| 4.1.9–4.1.10 | `typ`, `cty` media types; `application/` may be omitted | ✅ Media-type comparison | `typeMatches` · `TestTypeMatchesMediaTypeRules` |
| 4.1.11 | `crit`: reject if any listed extension is not understood; not empty; no registered names | ✅ No extension is implemented, so any `crit` is rejected before key lookup | `checkCritical` · `TestParseRejectsCriticalHeaders`, `TestCriticalHeaderCheckedBeforeKeyLookup` |
| 4.2–4.3 | Public / private header parameters | ✅ Ignored unless listed in `crit` | — |
| 5.1 | Message signature creation | ✅ `Sign` | `TestSignParseRoundTripAllFamilies`, `interop/TestJWS_OursVerifiedElsewhere` |
| 5.2 | Validation steps (decode, understood params, verify over the received ASCII input) | ✅ | `parseVerified` · `TestKnownAnswerJWS`, `interop/TestJWS_ElsewhereVerifiedByOurs` |
| 5.3 | Exact string comparison | ✅ | `TestParseClaimNamesAreCaseSensitive` |
| 6 | Key identification | ✅ `kid` only | — |
| 7.1 | Compact serialization | ✅ | `split3` · `TestSplit3`, `TestParseMalformedTokens` |
| 7.2 | JSON serialization (general / flattened), multiple signatures | ⛔ Compact-only library; tokens travel in HTTP headers | — |
| 10.7 | Algorithm validation | ✅ | see §4.1.1 |
| App. A.1–A.4 | Examples | ✅ Known-answer tests | `testdata/vectors/jose.json` · `TestKnownAnswerJWS` |
| App. A.5 | Unsecured JWS | ✅ Rejected | `TestKnownAnswerUnsecuredJWSRejected` |
| App. F | Detached content | ⛔ Not supported | — |

## RFC 7516 — JSON Web Encryption (JWE)

| § | Requirement | Status | Implementation · Tests |
|---|---|---|---|
| 4.1.1–4.1.2 | `alg` and `enc` REQUIRED and understood | ✅ Both required; both mandatory allowlists in `DecryptClaims`, checked before the `Decrypter` | `parseJWEProtected`, `DecryptClaims` · `TestDecryptClaimsRequiresAllowlists`, `TestDecryptClaimsEnforcesAllowlists`, `TestDecryptClaimsAllowlistAppliesToCustomDecrypter` |
| 4.1.3 | `zip` | ⛔ Compression unsupported, so `zip` is refused (removes decompression-bomb risk, RFC 8725 §3.6) | `TestDecryptRejectsZipAndCrit` |
| 4.1.4–4.1.12 | `jku`, `jwk`, `kid`, `x5*`, `typ`, `cty` | ✅ `kid`, `typ`, `cty` modeled; `typ` checked by `WithRequiredType`; others ignored, never dereferenced | `TestDecryptClaimsRequiredType` |
| 4.1.13 | `crit` | ✅ Rejected as for JWS | `TestDecryptRejectsZipAndCrit` |
| 5.1 | Encryption | ✅ | `TestJWERoundTripAllAlgorithms`, `interop/TestJWE_OursDecryptedByGoJose` |
| 5.2 | Decryption; AAD = ASCII(BASE64URL(protected header)); fail on tag mismatch | ✅ Single generic error, no plaintext on failure | `jwe.go` `Decrypt` · `TestJWEFailsClosedOnTamper`, `TestKnownAnswerJWE`, `interop/TestJWE_GoJoseDecryptedByOurs` |
| 7.1 | Compact serialization | ✅ 1 MiB cap | `TestDecryptRejectsOversizedInput`, `TestJWEMalformedCompact` |
| 7.2 | JSON serialization, multiple recipients, JWE AAD | ⛔ Compact-only | — |
| 9 | Distinguishing JWS from JWE | ✅ By segment count | `TestSplit3`, `TestJWEMalformedCompact` |
| 11.5 | Timing attacks on decryption | ✅ Every failure collapses to `ErrDecryptionFailed`; RSA-OAEP via constant-time `crypto/rsa` | `TestJWERejectsWrongRecipient` |

## RFC 7517 — JSON Web Key (JWK)

| § | Requirement | Status | Implementation · Tests |
|---|---|---|---|
| 4 | JWK is a JSON object; member names unique | ✅ Strict decoding | `Key.UnmarshalJSON` · `TestParseKeyRejectsNonCanonicalMaterial` |
| 4.1 | `kty` REQUIRED | ✅ `RSA`, `EC`, `OKP`, `oct` | `ParseKey` · `TestParseKey` |
| 4.2 | `use`: `sig` / `enc` | ✅ A key with `use` ≠ `sig` cannot verify | `permitsVerify` · `TestParseHonorsJWKUsageConstraints` |
| 4.3 | `key_ops`; no duplicates; consistent with `use` | ✅ Must include `verify` to verify; duplicates and inconsistency rejected | `TestKeyOpsRoundTripAndValidation` |
| 4.4 | `alg` | ✅ Key only verifies its own algorithm (`EdDSA` ≡ `Ed25519`, RFC 9864 §5) | `TestHMACKeyUsageConstraints`, `TestJWKAlgEdDSAAndEd25519AreTheSameKey` |
| 4.5 | `kid` | ✅ | `TestKeySetAddReplaceRemoveLookup` |
| 4.6–4.9 | `x5u`, `x5c`, `x5t`, `x5t#S256` members | ⛔ Not modeled; a JWK carrying them still parses, they are dropped | — |
| 5 | JWK Set `keys` REQUIRED | ✅ | `ParseKeySet` · `TestParseKeySet` |
| 5 | Implementations SHOULD ignore JWKs they do not understand or that are malformed | ⚠️ Unknown `kty` values are kept (and cannot verify); a **malformed** member fails the whole set. Silently dropping keys hides publisher errors and can turn a key rotation into an outage without any signal (spec §5.3). | `TestParseKeySet` |
| 8.1.1 (IANA) | `oct` keys never published | ✅ `MarshalJSON` refuses `oct` | `TestOctKeyDoesNotMarshal`, `TestKeySetMarshalJSON` |
| 9.1 | Key provenance: obtain keys over TLS | ✅ `KeyFetcher` is HTTPS-only on every redirect hop | `TestKeyFetcherRejectsRedirectToHTTP` |

## RFC 7518 — JSON Web Algorithms (JWA)

Implementation requirement levels are those of the IANA JOSE registry.

### JWS (§3)

| Algorithm | IANA level | Status | Tests |
|---|---|---|---|
| HS256 / HS384 / HS512 (§3.2) | Required / Optional | ✅ Sign + verify; key ≥ hash size, constant-time compare | `TestHMACRejectsShortKey`, `TestHMACVerifyRejectsTampered`, `TestKnownAnswerJWS` |
| RS256 / RS384 / RS512 (§3.3) | Recommended / Optional | 🟡 Verify only (≥ 2048 bits). Signing is withheld to steer new tokens to PSS/ECDSA/Ed25519 (spec §0.2); verification is needed for major IdPs. | `TestRSAPKCS1VerifyOnly`, `TestRSARejectsWeakKey`, `TestKnownAnswerJWS` |
| ES256 / ES384 / ES512 (§3.4) | Recommended+ / Optional | ✅ Sign + verify; fixed-length `R‖S`, curve must match | `TestECDSARejectsCurveMismatch`, `TestKnownAnswerJWS` |
| PS256 / PS384 / PS512 (§3.5) | Optional | ✅ Sign + verify; salt = hash size | `TestRSAPSSRoundTrip`, `TestKnownAnswerJWS` (PS384) |
| none (§3.6) | Optional | ⛔ Never implemented, never accepted (RFC 8725 §3.2) | `TestParseRejectsAlgNone` |

### JWE key management (§4)

| Algorithm | IANA level | Status | Tests |
|---|---|---|---|
| RSA1_5 (§4.2) | Recommended- | ⛔ Padding-oracle prone; being deprecated (draft-ietf-jose-deprecate-none-rsa15) | — |
| RSA-OAEP (§4.3, SHA-1) | Recommended+ | ⛔ Only the SHA-256 variant is offered | — |
| RSA-OAEP-256 (§4.3) | Optional | ✅ ≥ 2048 bits | `TestJWERoundTripAllAlgorithms`, `interop/` |
| A128KW / A192KW (§4.4) | Recommended / Optional | ⛔ Only A256KW | — |
| A256KW (§4.4) | Recommended | ✅ RFC 3394 | `TestKnownAnswerAESKeyWrapRFC3394` |
| dir (§4.5) | Recommended | ✅ | `TestKnownAnswerJWE` |
| ECDH-ES (§4.6) | Recommended+ | ✅ P-256/384/521; `epk` required and validated on-curve; `apu`/`apv` in the Concat KDF | `TestConcatKDFRFC7518AppendixC`, `TestDecryptECDHESWithPartyInfoRFC7518AppendixC`, `TestDecryptECDHESRejectsBadPartyInfoAndEPK` |
| ECDH-ES+A128KW / +A192KW (§4.6) | Recommended / Optional | ⛔ Only +A256KW | — |
| ECDH-ES+A256KW (§4.6) | Recommended | ✅ AlgorithmID = `alg` | `TestDecryptECDHESWithPartyInfoKeyWrap`, `interop/` |
| A*GCMKW (§4.7), PBES2 (§4.8) | Optional | ⛔ | — |

### JWE content encryption (§5)

| Algorithm | IANA level | Status |
|---|---|---|
| A128CBC-HS256 / A256CBC-HS512 (§5.2) | **Required** | ⚠️ Not implemented. The library limits JWE to AES-GCM (spec §3.1): no identified producer requires CBC-HMAC, and it avoids the MAC-then-decrypt construction. A caller can still supply its own `Decrypter`. |
| A192CBC-HS384 (§5.2) | Optional | ⛔ Same reason |
| A128GCM / A192GCM / A256GCM (§5.3) | Recommended / Optional / Recommended | ✅ 96-bit IV, 128-bit tag enforced — `TestJWERoundTripAllAlgorithms`, `TestKnownAnswerJWE` |

### Keys (§6)

| § | Requirement | Status | Tests |
|---|---|---|---|
| 6.2.1.2–6.2.1.3 | EC `x`/`y` are the full coordinate length | ✅ Exact length required | `TestParseKeyRejectsNonCanonicalMaterial`, `TestCanonicalKeyMaterialStillParses` |
| 6.3.1.1–6.3.1.2 | RSA `n`/`e` use the minimum number of octets | ✅ Leading zeros rejected | `TestParseKeyRejectsNonCanonicalMaterial` |
| 6.3.2 | RSA private key members | ⛔ Private keys are parsed from DER/SSH (`ParsePKCS8PrivateKey`, …), not from JWK | — |
| 6.4 | `oct` `k` | ✅ | `TestSecretRejectsEmptyOct` |

## RFC 7519 — JSON Web Token (JWT)

| § | Requirement | Status | Implementation · Tests |
|---|---|---|---|
| 2 | NumericDate is a JSON number | ✅ JSON numbers only, years 1–9999 | `NumericDate` · `TestNumericDateStrict`, `TestParseRejectsNonNumericDates` |
| 4 | Claim names unique | ✅ Duplicates rejected | `TestParseRejectsDuplicateMemberNames` |
| 4.1.1 `iss` | Application-specific processing | 🟡 Checked when `WithIssuer` is given (RFC 8725 §3.8 recommends it) | `TestParseIssuerAndAudience` |
| 4.1.2 `sub` | Application-specific | 🟡 Exposed; not validated | — |
| 4.1.3 `aud` | Reject if present and the principal does not identify with it | ✅ Enforced by default; `WithoutAudienceCheck` is an explicit opt-out | `TestParseAudienceEnforcement`, `TestDecryptClaimsAudienceEnforcement` |
| 4.1.4 `exp` | MUST NOT accept on or after `exp` | ✅ Optional leeway | `TestParseTimeChecks` |
| 4.1.5 `nbf` | MUST NOT accept before `nbf` | ✅ Optional leeway | `TestParseTimeChecks` |
| 4.1.6 `iat` | Informational | 🟡 Exposed; not validated | — |
| 4.1.7 `jti` | Unique ID; replay prevention | 🟡 Exposed; replay/revocation via `RevocationStore` | `TestRevocationStoreConformance` |
| 4.2–4.3 | Public / private claims | ✅ Any caller struct or map | `TestParseStrictDecodingKeepsProviderStructsWorking` |
| 5.1 `typ` | `JWT` recommended | ✅ `Sign` sets `typ: JWT` by default | `TestSignStampsDefaultType` |
| 5.2 `cty` | `JWT` for nested JWTs | 🟡 Settable with `WithContentType`; nested JWTs are not unwrapped automatically | — |
| 5.3 | Claims replicated as header parameters | ⛔ Not supported | — |
| 6 | Unsecured JWTs | ⛔ Always rejected | `TestKnownAnswerUnsecuredJWSRejected` |
| 7.1 | Creating a JWT | ✅ `Sign`, `EncryptClaims` | — |
| 7.2 | Validating a JWT (steps 1–10) | ✅ Step order documented in `parseVerified`; step 10 claims set must be an object | `TestParseRejectsNonObjectPayload` |
| 7.3 | String comparison | ✅ Exact | — |
| 8 | "HS256 and `none` MUST be implemented" | ⚠️ `none` is deliberately not implemented, following RFC 8725 §3.2 which updates RFC 7519 | — |
| 8 | RS256, ES256 RECOMMENDED | ✅ (RS256 verify-only) | — |

## RFC 7638 — JWK Thumbprint

| § | Requirement | Status | Tests |
|---|---|---|---|
| 3.1–3.2 | Required members only, lexicographic order, no whitespace | ✅ | `TestThumbprintRFC7638Vector`, `TestThumbprintPerKeyType`, `TestKnownAnswerThumbprintRFC8037` |
| 3.3 | Canonical key representation | ✅ Non-canonical JWKs rejected, so one key has one thumbprint | `TestThumbprintIsUniquePerKey` |
| 3.4 | Hash choice; SHA-256 by default | ✅ Optional `crypto.Hash` | `TestThumbprintOtherHash`, `TestThumbprintUnavailableHash` |

## RFC 7800 — Proof-of-Possession Key Semantics

| § | Requirement | Status | Tests |
|---|---|---|---|
| 3.1 | `cnf` claim | ✅ `RegisteredClaims.Confirmation` | `TestConfirmationJSON` |
| 3.2 | `cnf.jwk` | ✅ | `TestConfirmationJWKRoundTrip` |
| 3.3 | `cnf.jwe` (encrypted key) | ⛔ Not modeled | — |
| 3.4 | `cnf.kid` | ⛔ Not modeled | — |
| (RFC 9449 / 8705) | `cnf.jkt` | ✅ Modeled; computed with `Thumbprint` | `TestConfirmationJSON` |
| 5–6 | Verifying the proof of possession | 🟡 Caller's responsibility (depends on the PoP protocol, e.g. DPoP) | — |

## RFC 8037 — CFRG curves in JOSE

| § | Requirement | Status | Tests |
|---|---|---|---|
| 2 | OKP key type, `crv`, `x` | ✅ Ed25519 only; `x` must be 32 bytes | `TestParseKeyRejectsNonCanonicalMaterial`, `TestEd25519RequiresEd25519Curve` |
| 2 | OKP private key `d` | ⛔ Private keys come from raw/DER/SSH parsers | `TestParseEd25519Raw` |
| 3.1 | EdDSA signatures (Ed25519) | ✅ Now identified as `Ed25519` (RFC 9864) | `TestEd25519SignatureMatchesRFC8037Vector`, `TestParseRFC8037LegacyVectorVerifies` |
| 3.1 | Ed448 | ⛔ Not in the Go standard library | — |
| 3.2 | ECDH-ES with X25519 / X448 | ⛔ Not offered for JWE | — |
| App. A.3 | Thumbprint example | ✅ | `TestKnownAnswerThumbprintRFC8037` |

## RFC 9864 — Fully-Specified Algorithms for JOSE

| § | Requirement | Status | Tests |
|---|---|---|---|
| 2.2 | `Ed25519` JWS algorithm | ✅ Emitted by `NewEd25519Signer` | `TestEd25519SignerEmitsFullySpecifiedAlg`, `interop/` (golang-jwt with alias) |
| 4.1.2 / 4.4 | `EdDSA` Deprecated: the replacement SHOULD be used | ✅ Never emitted; verified only when explicitly allowlisted, marked `Deprecated:` | `TestParseEd25519AllowlistIsExplicit` |
| 5 | Key representation unchanged apart from `alg` | ✅ `EdDSA` and `Ed25519` JWK `alg` interchangeable | `TestJWKAlgEdDSAAndEd25519AreTheSameKey` |
| 3 | Fully-specified encryption | ✅ All built-in JWE algorithms are fully specified | — |

Interoperability note: `go-jose/v4` does not know `Ed25519` yet (those interop
subtests are skipped with that reason); `golang-jwt/v5` needs the one-line
alias shown in `interop/jws_test.go`.

## RFC 8725 — JWT Best Current Practices

| § | Practice | Status | Tests |
|---|---|---|---|
| 3.1 | Perform algorithm verification | ✅ Mandatory allowlists (JWS, JWE `alg` and `enc`), key usage honored | `TestParseRequiresAllowlist`, `TestDecryptClaimsRequiresAllowlists`, `TestParseAlgConfusionRSAasHMAC` |
| 3.2 | Use appropriate algorithms | ✅ No `none`, RSA1_5 or CBC-HMAC; RSA ≥ 2048 | `TestRSARejectsWeakKey` |
| 3.3 | Validate all cryptographic operations | ✅ Nested JWTs are not unwrapped, so no partially validated layers | — |
| 3.4 | Validate cryptographic inputs (e.g. ECDH points) | ✅ | `TestDecryptECDHESRejectsBadPartyInfoAndEPK` |
| 3.5 | Ensure cryptographic keys have sufficient entropy | 🟡 Minimum HMAC key length enforced; entropy of caller-supplied secrets cannot be measured | `TestHMACRejectsShortKey` |
| 3.6 | Avoid compression of encryption inputs | ✅ `zip` refused | `TestDecryptRejectsZipAndCrit` |
| 3.7 | Use UTF-8 | ✅ Invalid UTF-8 rejected | `TestParseRejectsInvalidUTF8` |
| 3.8 | Validate issuer and subject | 🟡 `WithIssuer`; subject semantics are application-specific | `TestParseIssuerAndAudience` |
| 3.9 | Use and validate audience | ✅ Enforced by default | `TestParseAudienceEnforcement` |
| 3.10 | Do not trust received claims (`kid`, `jku`, `x5u`) | ✅ Never dereferenced; `kid` is only a lookup key; JWKS fetching hardened (HTTPS-only redirects, size cap, rate limit) | `TestKeyFetcherRejectsRedirectToHTTP`, `TestKeyFetcherSingleFlightColdStart` |
| 3.11 | Use explicit typing | ✅ `Sign` always sets `typ`; `WithRequiredType` compares it for JWS and JWE | `TestParseRequiredTypeRejectsForeignMediaType`, `TestDecryptClaimsRequiredType` |
| 3.12 | Use mutually exclusive validation rules for different kinds of JWTs | 🟡 Combine `WithRequiredType`, `WithIssuer`, `WithAudience` per token kind (see README) | — |

## RFC 6750 — Bearer Token Usage

| § | Requirement | Status | Tests |
|---|---|---|---|
| 2.1 | `Authorization: Bearer` with `b64token` syntax | ✅ Strict syntax, `1*SP`, single header | `TestBearerTokenSyntax`, `TestBearerTokenRejectsMultipleAuthorizationHeaders` |
| 2.2 | Form-encoded body parameter | ⛔ Not supported (MAY) | — |
| 2.3 | URI query parameter | ⛔ Not supported (SHOULD NOT be used) | — |
| 3 | `WWW-Authenticate: Bearer` challenge; `realm`; no error code when credentials are missing | ✅ | `TestWriteChallengeMapping`, `TestMiddlewareRealmAndReporting` |
| 3.1 | `invalid_request` 400, `invalid_token` 401, `insufficient_scope` 403 (+ `scope`) | ✅ Fixed descriptions; infrastructure failures are 5xx, not `invalid_token` | `TestWriteChallengeMapping`, `TestWriteInsufficientScope`, `TestMiddlewareInfrastructureFailureIs503AndReported` |
| 5.3 | Transport and storage recommendations (TLS, no cookies) | 🟡 Deployment concern | — |

## RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens

| § | Requirement | Status | Tests |
|---|---|---|---|
| 2.1 | `typ` MUST be `at+jwt` | ✅ Issuers: `WithType(AccessTokenType)` | `TestSignOptions` |
| 2.2 | REQUIRED `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`; `jti` | ✅ `ValidateAccessTokenClaims` (`jti` is only RECOMMENDED) | `TestValidateAccessTokenClaims`, `TestValidateAccessTokenClaimsNamesEveryMissingClaim` |
| 2.2.1–2.2.3 | `auth_time`, `acr`, `amr`, `scope`, `groups`, `roles`, `entitlements` | ✅ `AccessTokenClaims` | `TestAccessTokenClaimsFlatJSON` |
| 4 | Resource server MUST check `typ`, `iss`, `aud`, signature algorithm, `exp` | 🟡 All available; the caller combines them: `WithRequiredType(AccessTokenType)`, `WithIssuer`, `WithAudience`, `WithAllowedAlgorithms`, then `ValidateAccessTokenClaims` (see README) | — |
| 4 | Obtain keys from AS metadata `jwks_uri` (RFC 8414) | 🟡 Pass the URI to `NewKeyFetcher`; `DiscoverJWKSURI` implements OIDC Discovery, not RFC 8414 | — |
| 4 | Scope-based authorization | 🟡 Application logic; `WriteInsufficientScope` for the response | `TestWriteInsufficientScope` |

## OpenID Connect Core 1.0 and Discovery 1.0

| Section | Requirement | Status | Tests |
|---|---|---|---|
| Core §2 | ID token REQUIRED claims `iss`, `sub`, `aud`, `exp`, `iat` | 🟡 Modeled; enforce with `WithRequiredClaims` | `TestGoogleIDTokenFixture`, `TestOktaIDTokenFixture`, `TestEntraIDTokenDocumentedClaims` |
| Core §5.1 | Standard claims | ✅ `StandardClaims`, `Address`; string-typed booleans accepted | `TestProviderFixturesRoundTrip`, `TestBoolAcceptsOIDCProviderForms` |
| Core §3.1.3.7 step 2 | `iss` MUST match | 🟡 `WithIssuer` | — |
| Core §3.1.3.7 step 3 | `aud` MUST contain the client ID | ✅ `WithAudience`; a foreign `aud` is rejected by default | `TestParseAudienceEnforcement` |
| Core §3.1.3.7 step 3 | Reject additional untrusted audiences | 🟡 Inspect `Audience` after parsing | — |
| Core §3.1.3.7 steps 4–5 | `azp` checks | 🟡 `GoogleClaims.AuthorizedParty`; relying-party logic | — |
| Core §3.1.3.7 steps 6–8 | Signature validation with the negotiated `alg` | ✅ `WithAllowedAlgorithms` | — |
| Core §3.1.3.7 step 9 | `exp` | ✅ | `TestParseTimeChecks` |
| Core §3.1.3.7 step 10 | `iat` too far away (MAY) | 🟡 Not validated | — |
| Core §3.1.3.7 step 11 | `nonce` MUST match the request value | 🟡 Relying-party flow state, out of scope; compare `StandardClaims.Nonce` | — |
| Core §3.1.3.7 steps 12–13 | `acr`, `auth_time` / `max_age` | 🟡 Relying-party logic | — |
| Discovery §4 | Well-known path, trailing `/` removed | ✅ | `TestDiscoverJWKSURITrailingSlashIssuer` |
| Discovery §4.3 | Returned `issuer` MUST equal the requested one; TLS | ✅ No fallback URL | `TestDiscoverJWKSURIRejections`, `TestDiscoverJWKSURINoSilentFallback` |

---

## Standards tracked for changes

| Document | Status (2026-09-16) | Relevance |
|---|---|---|
| RFC 9864 | Published; updates RFC 7518 and RFC 8037 | Implemented (above) |
| draft-ietf-oauth-rfc8725bis | In the RFC Editor queue | Will update RFC 8725; re-check §3 once published |
| draft-ietf-jose-deprecate-none-rsa15 | Publication requested | No code impact: neither `none` nor RSA1_5 is supported |
| RFC 8996, RFC 9700 | Published; update RFC 6750 | Deployment guidance (TLS 1.2+, OAuth security BCP) |

The weekly `standards-watch` workflow checks RFC status and errata, the IANA
JOSE and JWT registries, and these drafts, and opens an issue when something
changes.
