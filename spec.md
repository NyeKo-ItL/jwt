# `jwt` — Shared JWT/JOSE Library — Specification

Status: final — this document is the `spec.md` intended to seed the new,
standalone public repository. Everything it describes (code, comments, docs)
ships in English.

The Go module path (i.e. which GitHub repo this becomes, and its import
path) is a repository-setup decision made by whoever creates the repo. It is
intentionally not specified in this document — every code example below
shows only the package identifier, `jwt`, as it will be imported once the
module exists.

---

## 0. Governing design decisions

These are binding constraints on everything that follows, not suggestions:

1. **One package, not many.** Every concern in this spec — JWS, JWE, JWK/JWKS,
   OIDC provider claims, the RFC 9068 access-token profile, opaque tokens,
   revocation, the HTTP bearer adapter, key-material parsing — lives in a
   single package, `jwt`, organized internally into cohesive files (§7), not
   into sub-packages. This mirrors how large standard-library packages stay
   single-package despite covering many concerns (`encoding/json` spans
   encode/decode/scan/stream/tags in one package; `crypto/tls` spans the
   handshake, cipher suites, and session cache in one package) rather than
   forcing every caller to juggle a dozen import paths for one coherent
   concept. Splitting into sub-packages is exactly the kind of premature
   structure that makes a small library tedious to write against.
2. **Signing is curated; verifying is permissive; both stay open to
   extension.** For every key type, the library only _ships_ a built-in
   `Signer` constructor for the single best-practice algorithm(s) of that
   family. `Verifier` construction, by contrast, covers the _entire_
   applicable JWA/EdDSA algorithm registry, because the library must be able
   to validate tokens minted by third parties (Google, Okta, Microsoft Entra
   ID, and any other conformant issuer) that may use an algorithm the library
   would never choose itself. Concretely:
   - HMAC: `HS256`/`HS384`/`HS512` — all three are "best" for their
     respective output sizes; all are signable and verifiable.
   - RSA: **built-in signing is PS256/PS384/PS512 (RSA-PSS) only.**
     `RS256`/`RS384`/`RS512` (PKCS#1 v1.5) are **built-in verify-only** —
     Google, Okta, and Entra ID all issue `RS256` ID tokens today, so
     verification must support it, but the library will never itself
     produce a PKCS#1 v1.5 signature _out of the box_.
   - ECDSA: `ES256`/`ES384`/`ES512` — sign and verify (algorithm choice
     already tracks curve strength, so there is no weaker-variant problem).
   - EdDSA: `Ed25519` — sign and verify; the only OKP algorithm in play.
   - **Crucially, "curated" describes the built-in constructors, not a
     closed type system.** `Signer` and `Verifier` are plain interfaces
     (§5.1). Nothing stops a caller from implementing `Signer` themselves
     for RS256, or for an HSM/KMS-backed key, or for any algorithm this
     library has never heard of — `jwt.Sign` takes a `Signer`, full stop,
     with no internal type-switch over a closed set of "known" signers.
     `Algorithm` is an open `string` type, not a sealed enum, specifically so
     a caller-defined algorithm identifier works exactly like a built-in one.
     See §5.1 for a worked example.
   - **`alg: none` (RFC 7518 §3.6) is the one deliberate exception: it is
     never representable, in either direction, under any circumstance**, and
     that is not something a custom `Signer`/`Verifier` can be used to route
     around, since `Parse`'s mandatory allowlist (§4.1) is checked
     independently of what the resolved key claims to support.
3. **RFC compliance is a single mandatory bar, not a tiered wishlist.** JWT,
   JWS, JWA, EdDSA-in-JOSE, JWK, JWK Thumbprint, the JWT BCP, Bearer Token
   Usage, JWE, the OAuth 2.0 JWT access-token profile, and PoP confirmation
   claims are all required for v1.0 (§3).
4. **Every RFC-registered generic JWT claim is modeled** (§2.1, §5.1).
5. **OIDC provider interoperability is a first-class claims concern**: the
   standard OpenID Connect claims plus the specific extension claims used by
   Google, Okta, and Microsoft Entra ID ship as ready-made types (§5.4).
6. **Every storage-shaped concern is an injectable interface**, never a hard
   dependency on the library's own in-memory default. This applies to JWKS
   key resolution (§5.3) and to revocation state (§5.6).
7. **The library never touches the filesystem and never invents key
   material.** No file loading, no file-permission checks, no ephemeral/dev
   key generation. Every function that needs key material takes `[]byte`
   (or a stdlib `crypto.*` type) that the caller already produced by
   whatever means it prefers. Format parsing is explicit per encoding — no
   auto-detection/guessing across PEM, hex, base64, or raw (§5.9).
8. **Opaque (non-JWT) tokens have exactly two constructors**: one that
   generates a fresh random token, one that deterministically derives a
   token-shaped value from a string the caller already holds (§5.5).
9. **API surface follows established Go conventions for shared libraries**
   (§6) so that consuming code stays short and obvious — this is a design
   goal in its own right, not just a byproduct of the other decisions.

---

## 1. Why this exists

Hand-rolled JWT signing/verification, JWKS handling, and opaque
refresh-token bookkeeping tend to be reimplemented slightly differently
every time a new service needs them — ad hoc base64url header construction,
ad hoc key parsers, ad hoc SHA-256 refresh-token hashing, ad hoc JTI
denylists, ad hoc alg-confusion guards. `jwt` consolidates the reusable
parts — JWS signing/verification across algorithm families, JWE encryption,
JWK/JWKS handling with pluggable resolution, OIDC-standard and
provider-specific claim sets, opaque token utilities, and a thin HTTP
bearer-auth adapter — into one tested, RFC-referenced package any Go service
can import instead of rebuilding these primitives from scratch.

---

## 2. Feature inventory

### 2.1 In scope

| Feature                                                                                                                                 | Design decision applied                                                                                                                                                                  |
| --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWS compact sign/verify (HMAC)                                                                                                          | Built-in sign + verify, all three sizes (§0.2)                                                                                                                                           |
| JWS compact sign/verify (RSA)                                                                                                           | Built-in **verify** RS256/384/512 (needed for common external IdPs' ID tokens); built-in **sign** PS256/384/512 only; RS256 _signing_ is available by implementing `Signer` (§0.2, §5.1) |
| JWS compact sign/verify (ECDSA)                                                                                                         | Built-in sign + verify, all three curves                                                                                                                                                 |
| JWS compact sign/verify (EdDSA/Ed25519)                                                                                                 | Built-in sign + verify                                                                                                                                                                   |
| JWE encrypt/decrypt                                                                                                                     | No legacy-interop requirement identified, so modern algorithm set only, both directions (§3.1)                                                                                           |
| All RFC 7519 §4.1 registered claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`)                                                   | Complete by construction (§0.4)                                                                                                                                                          |
| RFC 7800 `cnf` (confirmation/PoP) claim                                                                                                 | Part of `RegisteredClaims` (§5.1)                                                                                                                                                        |
| Full RFC 7515 §4.1 JOSE header parameter set (`alg`, `typ`, `cty`, `kid`, `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `crit`)        | All fields modeled and parsed; `jku`/`x5u`/`jwk`/`x5c` are exposed for inspection but never auto-dereferenced (RFC 8725 §3.9–3.10)                                                       |
| OIDC standard claims (OpenID Connect Core §5.1)                                                                                         | `StandardClaims` (§5.4)                                                                                                                                                                  |
| Google-specific ID token claims (`hd`, `azp`, `at_hash`)                                                                                | `GoogleClaims`                                                                                                                                                                           |
| Okta-specific ID token claims (`ver`, `auth_time`, `amr`, `idp`, `groups`)                                                              | `OktaClaims`                                                                                                                                                                             |
| Microsoft Entra ID claims (`tid`, `oid`, `upn`, `roles`, `groups`, `appid`, `ver`, `unique_name`)                                       | `EntraClaims`                                                                                                                                                                            |
| RFC 9068 JWT access-token profile (`client_id`, `scope`, required claims, `typ: at+jwt`)                                                | `AccessTokenClaims` (§5.8)                                                                                                                                                               |
| Algorithm allowlisting / anti "alg confusion"                                                                                           | Mandatory, structural (§0.2, §4)                                                                                                                                                         |
| Issuer / audience / expiry / not-before validation                                                                                      |                                                                                                                                                                                          |
| "Parse without verifying signature/expiry" (read-only claim peek)                                                                       | `ParseInsecure`, loudly named (§5.1)                                                                                                                                                     |
| JWK / JWKS representation, covering every algorithm family in scope (RSA, EC, OKP; `oct` for internal-only use)                         | Full `KeyType` coverage; `oct` keys refuse to marshal into a servable JWKS document (§5.3)                                                                                               |
| JWK lookup by `kid` via an **injectable `KeyProvider` interface**                                                                       | `KeyProvider` interface; ships `KeySet` and `KeyFetcher` as built-ins, but any Redis/DB-backed implementation can be injected (§5.3)                                                     |
| JWK Thumbprint, computable directly from a caller-supplied key `[]byte`                                                                 | `ThumbprintBytes(kty, raw []byte, hash)`, alongside `Thumbprint(Key, hash)`; used as the identifier for key-level revocation (§5.6)                                                      |
| Key parsing from explicit, caller-decoded `[]byte` (PKCS#1, PKCS#8, SEC1, OpenSSH, raw Ed25519 seed/expanded, PKIX public key)          | One function per exact encoding, no auto-detection (§0.7, §5.9)                                                                                                                          |
| Opaque token generation                                                                                                                 | Exactly two constructors: `NewOpaqueToken()` and `DeriveOpaqueToken(s)` (§0.8, §5.5)                                                                                                     |
| Opaque token hashing + constant-time compare                                                                                            | `Hash`, `Equal` via `crypto/subtle`                                                                                                                                                      |
| Refresh-token rotation with reuse detection ("family" revocation)                                                                       | `TokenFamily` / `RotationResult`                                                                                                                                                         |
| Revocation abstraction, generalized over identifier namespace (`jti`, `kid`, session/family id) via an **injectable `RevocationStore`** | `RevocationStore` interface; ships `MemoryRevocationStore` (§5.6)                                                                                                                        |
| HTTP Bearer token extraction (`Authorization: Bearer <token>`)                                                                          | `BearerToken`                                                                                                                                                                            |
| `WWW-Authenticate` challenge header construction                                                                                        | `WriteChallenge`                                                                                                                                                                         |

### 2.2 Explicitly out of scope

| Feature                                                                                                                                 | Why excluded                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full OAuth 2.1 Authorization Server (authorization code grant, PKCE, dynamic client registration, AS/PRM metadata, revocation endpoint) | A distinct product (an authorization _server_), not a JWT/JOSE concern. Candidate for a separate companion module built **on top of** `jwt`, not folded into it.                                          |
| OIDC relying-party flow (code exchange, nonce/state cookies, provider discovery orchestration)                                          | Application-level HTTP orchestration. `jwt` supplies the primitives an RP needs (`KeyProvider`-based ID-token verification, provider claim shapes); the flow itself belongs in the consuming application. |
| VAPID header framing (`Authorization: vapid t=..., k=...`)                                                                              | Transport framing specific to Web Push, not JOSE. The underlying ES256 JWS signing is in scope; the header format is not.                                                                                 |
| Session/user data model, RBAC/role-level checks                                                                                         | Product-specific authorization logic, not token mechanics.                                                                                                                                                |
| File loading, file-permission hardening, ephemeral/dev key generation                                                                   | The library takes `[]byte`/`crypto.*` only; callers own file I/O, decoding, and key generation (§0.7).                                                                                                    |
| RFC 6749/7009/7636/7591/8414/9728/8707 (OAuth AS mechanics)                                                                             | These define an authorization server, not a JWT/JOSE library. Same reasoning as the AS row above.                                                                                                         |

---

## 3. RFC compliance

All of the following are mandatory for v1.0 — there is no "optional tier."

| RFC                                                | Title                                   | Requirement                                                                                                                                                                                                                                    |
| -------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token (JWT)                    | Full claims set, `StringOrURI`, `NumericDate`, compact JWT structure.                                                                                                                                                                          |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature (JWS)                | Compact serialization; full §4.1 header parameter set (parsed, not all auto-actioned — see §2.1).                                                                                                                                              |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms (JWA)               | HS256/384/512, RS256/384/512 (built-in verify-only), PS256/384/512, ES256/384/512 — exact byte-level requirements (e.g. fixed-length concatenated ECDSA `r‖s`, not ASN.1 DER); §4/§5 key-management and content-encryption algorithms for JWE. |
| [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) | CFRG ECDH/EdDSA in JOSE                 | `EdDSA` with Ed25519 (`crv: Ed25519`), sign + verify.                                                                                                                                                                                          |
| [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) | JSON Web Encryption (JWE)               | Compact serialization; encrypt/decrypt with the algorithm set in §5.2.                                                                                                                                                                         |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key (JWK)                      | `kty: RSA/EC/OKP/oct` representation; `oct` never serialized into a document served over HTTP.                                                                                                                                                 |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK Thumbprint                          | Both from a parsed `Key` and directly from caller-supplied raw key bytes.                                                                                                                                                                      |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) | JWT Best Current Practices              | Mandatory algorithm allowlisting, `alg: none` unrepresentable, explicit `typ` checking, audience validation, no automatic `jku`/`x5u`/`jwk` dereferencing.                                                                                     |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | Bearer Token Usage                      | `Authorization: Bearer` extraction; `WWW-Authenticate` challenge format.                                                                                                                                                                       |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | JWT Profile for OAuth 2.0 Access Tokens | `AccessTokenClaims`: required claims, mandatory `typ: at+jwt`.                                                                                                                                                                                 |
| [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) | Proof-of-Possession Semantics (`cnf`)   | `cnf.jkt` (JWK Thumbprint confirmation) as part of `RegisteredClaims`.                                                                                                                                                                         |

Also referenced (not an RFC, but the source of the standard-claims
requirement in §2.1/§5.4): **OpenID Connect Core 1.0, §2 and §5.1** (OpenID
Foundation).

### 3.1 Not targeted, and why

RFC 6749 (OAuth 2.0), RFC 7009 (Token Revocation endpoint), RFC 7636 (PKCE),
RFC 7591 (Dynamic Client Registration), RFC 8414 (AS Metadata), RFC 9728
(Protected Resource Metadata), RFC 8707 (Resource Indicators) — these define
an _authorization server_, not a JWT/JOSE library (§2.2).

For JWE specifically: unlike JWS, there is no identified need to interoperate
with an existing third-party encrypted-token producer, so there is no
legacy-interop requirement pulling in older algorithms (e.g. `RSA1_5`,
AES-CBC+HMAC content encryption). Both encrypt and decrypt are therefore
restricted to the modern,
AEAD-based algorithm set in §5.2. As with JWS, this is a built-in-constructor
restriction, not a closed type system — an `Encrypter`/`Decrypter` for a
legacy algorithm can be implemented by a caller exactly like a custom
`Signer` (§0.2, §5.1).

---

## 4. Security requirements (non-negotiable, enforced by the library itself)

1. **Mandatory algorithm allowlist on every `Parse`/`Decrypt` call.** No
   "accept whatever the header says" mode exists, regardless of whether the
   `Signer`/`Verifier` involved is a built-in or a caller-supplied one.
2. **`alg: none` and JWE `"enc": none`-equivalent constructions are
   unrepresentable** — no built-in implementation exists for them, and the
   allowlist check happens independently of whatever a custom implementation
   reports, so a custom `Verifier` cannot be used to smuggle `none` past
   `Parse` either.
3. **Built-in signing is restricted to the curated best-practice set per key
   type (§0.2); built-in verification is not; both remain open to caller
   extension (§5.1).**
4. **Verified vs. unverified parsing are distinct, differently-named
   functions** (`Parse`/`Decrypt` vs `ParseInsecure`). The insecure path's
   result MUST NOT be used for any authorization decision — only read-only
   inspection (e.g. looking up a session by an expired token's `jti`).
5. **Constant-time comparisons** for all secret/hash comparisons (HMAC
   verification, opaque-token hash comparison) via `crypto/hmac.Equal` /
   `crypto/subtle.ConstantTimeCompare` — never `==` or `bytes.Equal`.
6. **Minimum key-size enforcement**: HMAC keys shorter than the hash's
   output size are rejected at construction time; RSA keys below 2048 bits
   are rejected (both for JWS and for JWE key management). This applies to
   every built-in constructor; it is, by construction, not something a
   custom `Signer`/`Verifier` can be forced to inherit — the library trusts
   the caller's own implementation the same way it trusts any interface
   implementation in Go.
7. **JWE decryption fails closed**: the AEAD tag is verified before any
   plaintext is returned; on failure the library returns a single generic
   error, never partial/unauthenticated plaintext.
8. **`jku`, `x5u`, `jwk`, `x5c` header parameters are never automatically
   dereferenced or trusted to select a verification key.** They are parsed
   and exposed for inspection only (RFC 8725 §3.9–3.10).
9. **`KeyProvider` and `RevocationStore` lookups both take a
   `context.Context`** so callers backing them with a network-bound store
   (Redis, a database, a remote JWKS fetch) can apply their own timeouts and
   cancellation.
10. **Anti-confusion check at resolution time**: when `Parse` resolves a
    `Key` via `KeyProvider.Lookup`, it verifies the `Key`'s own type/algorithm
    family matches the token header's `alg` before building a `Verifier` from
    it — an RSA `Key` can never be used to satisfy an `HS256` header.
11. **No panics on malformed input.** Every public parsing/decryption
    function returns `error`; malformed/truncated/oversized tokens must not
    panic or allocate unbounded memory.
12. **Clock is injectable** (`WithClock`) for every time-based check.

---

## 5. Public API design

Everything below lives in one package, `jwt`. Section numbers group
identifiers by concern for readability; they do not imply sub-packages.

### 5.1 Algorithms, signing & parsing (JWS core)

```go
// Algorithm identifies a JWA/EdDSA signing algorithm. It is an open string
// type, not a closed enum: a caller implementing a custom Signer/Verifier
// (see below) can define their own Algorithm value and it works exactly like
// a built-in one everywhere an Algorithm is accepted.
type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256" // built-in verify-only, see §0.2
	RS384 Algorithm = "RS384" // built-in verify-only
	RS512 Algorithm = "RS512" // built-in verify-only
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	EdDSA Algorithm = "EdDSA"
	// "none" (RFC 7518 §3.6) has no constant and no built-in Signer/Verifier,
	// and Parse's allowlist check (§4.1) cannot be satisfied by it even via a
	// custom implementation: see §4.2.
)

// Signer produces a JWS signature over the ASCII signing input
// ("<base64url header>.<base64url payload>", RFC 7515 §5.1).
//
// The library ships constructors for the curated best-practice algorithm
// per key type (§0.2): NewHMACSigner (HS256/384/512), NewRSAPSSSigner
// (PS256/384/512), NewECDSASigner (ES256/384/512), NewEd25519Signer (EdDSA).
// There is no built-in constructor for PKCS#1 v1.5 RSA signing (RS256/384/
// 512) — an application that must sign with it (e.g. for a legacy consumer,
// or a KMS/HSM-backed key that never leaves hardware) implements Signer
// directly; Sign has no type-switch over a closed set of "known" signers:
//
//	type kmsRS256Signer struct {
//		client *kms.Client
//		keyID  string
//	}
//
//	func (s *kmsRS256Signer) Algorithm() jwt.Algorithm { return jwt.RS256 }
//	func (s *kmsRS256Signer) KeyID() string            { return s.keyID }
//	func (s *kmsRS256Signer) Sign(signingInput []byte) ([]byte, error) {
//		return s.client.Sign(context.Background(), s.keyID, signingInput)
//	}
//
//	token, err := jwt.Sign(claims, &kmsRS256Signer{client: c, keyID: "..."})
type Signer interface {
	Algorithm() Algorithm
	KeyID() string // RFC 7515 §4.1.4 "kid"; empty if the key has none
	Sign(signingInput []byte) (signature []byte, err error)
}

// Verifier checks a JWS signature. The library ships constructors for the
// full applicable registry, including verify-only algorithms (RS256/384/
// 512), because it must validate tokens issued by third parties this
// library would never itself sign with. Like Signer, Verifier is a plain
// interface a caller can implement for any algorithm the built-ins don't
// cover.
type Verifier interface {
	Algorithm() Algorithm
	KeyID() string
	Verify(signingInput, signature []byte) error
}

func NewHMACSigner(alg Algorithm, key []byte, kid string) (Signer, error)
func NewHMACVerifier(alg Algorithm, key []byte, kid string) (Verifier, error)

func NewRSAPSSSigner(alg Algorithm, key *rsa.PrivateKey, kid string) (Signer, error)
func NewRSAPSSVerifier(alg Algorithm, key *rsa.PublicKey, kid string) (Verifier, error)
func NewRSAPKCS1Verifier(alg Algorithm, key *rsa.PublicKey, kid string) (Verifier, error) // RS256/384/512

func NewECDSASigner(alg Algorithm, key *ecdsa.PrivateKey, kid string) (Signer, error)
func NewECDSAVerifier(alg Algorithm, key *ecdsa.PublicKey, kid string) (Verifier, error)

func NewEd25519Signer(key ed25519.PrivateKey, kid string) (Signer, error)
func NewEd25519Verifier(key ed25519.PublicKey, kid string) (Verifier, error)

// KeyProvider resolves a Key by "kid" (may be empty, meaning "the only
// key"), used by both Parse (JWS verification) and Decrypt (JWE, §5.2). A
// single fixed key and a full JWKS-backed store satisfy the same interface —
// see §5.3.
type KeyProvider interface {
	Lookup(ctx context.Context, kid string) (Key, bool, error)
}

// Audience is RFC 7519 §4.1.3's StringOrURI-or-array claim, transparently
// (de)serialized from either a bare string or a JSON array.
type Audience []string

func (a Audience) MarshalJSON() ([]byte, error)
func (a *Audience) UnmarshalJSON(b []byte) error
func (a Audience) Has(v string) bool

// NumericDate is RFC 7519 §2's NumericDate, exposed as a time.Time.
type NumericDate struct{ time.Time }

func NewNumericDate(t time.Time) *NumericDate

// Confirmation is the RFC 7800 §3 "cnf" claim, binding a token to a
// possession key. JWKThumbprint ties directly into ThumbprintBytes (§5.3): a
// resource server can compute the thumbprint of the key used on the current
// connection/request and compare it against this value.
type Confirmation struct {
	JWKThumbprint string `json:"jkt,omitempty"` // RFC 7800 §3.3 + RFC 7638
	JWK           *Key   `json:"jwk,omitempty"` // RFC 7800 §3.2
}

// RegisteredClaims holds every generic claim registered against the IANA
// "JSON Web Token Claims" registry that this library targets: the original
// seven from RFC 7519 §4.1, plus "cnf" from RFC 7800.
type RegisteredClaims struct {
	Issuer       string        `json:"iss,omitempty"`
	Subject      string        `json:"sub,omitempty"`
	Audience     Audience      `json:"aud,omitempty"`
	ExpiresAt    *NumericDate  `json:"exp,omitempty"`
	NotBefore    *NumericDate  `json:"nbf,omitempty"`
	IssuedAt     *NumericDate  `json:"iat,omitempty"`
	ID           string        `json:"jti,omitempty"`
	Confirmation *Confirmation `json:"cnf,omitempty"`
}

// There is no Claims[T] wrapper: a "claims value" is any type that
// JSON-marshals to an object. Embed RegisteredClaims to get the registered
// members flattened natively by encoding/json:
//
//	type MyClaims struct {
//		jwt.RegisteredClaims
//		Scope string `json:"scope,omitempty"`
//	}
//
// That struct is what you pass to Sign / EncryptClaims and, as a *pointer,
// to Parse / DecryptClaims / ClaimsFromContext, which fill it in place — the
// type is inferred from the pointer, so calls carry no explicit type
// argument. RegisteredClaims may also be used on its own when there are no
// application claims.

// Header is the JOSE header (RFC 7515 §4.1), modeling every registered
// parameter. jku/x5u/jwk/x5c are parsed and readable but NEVER automatically
// dereferenced to select a verification key (§4.8).
type Header struct {
	Algorithm      Algorithm `json:"alg"`
	Type           string    `json:"typ,omitempty"`
	ContentType    string    `json:"cty,omitempty"`
	KeyID          string    `json:"kid,omitempty"`
	JWKSetURL      string    `json:"jku,omitempty"`
	JWK            *Key      `json:"jwk,omitempty"`
	X509URL        string    `json:"x5u,omitempty"`
	X509CertChain  []string  `json:"x5c,omitempty"`
	X509CertSHA1   string    `json:"x5t,omitempty"`
	X509CertSHA256 string    `json:"x5t#S256,omitempty"`
	Critical       []string  `json:"crit,omitempty"`
}

// SignOption customizes the JOSE header; it never affects "alg".
type SignOption func(*signConfig)

func WithType(typ string) SignOption        // override/omit "typ"; default DefaultType, AccessTokenType for RFC 9068
func WithContentType(cty string) SignOption // "cty" (RFC 7515 §4.1.10)

// Sign JSON-encodes a claims value (any type marshaling to an object) and
// produces a compact JWS (RFC 7515 §7.1).
func Sign[C any](claims C, signer Signer, opts ...SignOption) (string, error)

// Parse decodes a compact JWS, verifies its signature via keys, validates
// the registered claims according to opts, and unmarshals the payload into
// dst. dst's type is inferred:
//
//	var claims MyClaims
//	err := jwt.Parse(ctx, token, &claims, keys, jwt.WithAllowedAlgorithms(jwt.EdDSA))
//
// Registered-claim validation runs whether or not dst models them.
// WithAllowedAlgorithms is mandatory — Parse returns ErrNoAllowedAlgorithms
// if it is omitted.
func Parse[C any](ctx context.Context, token string, dst *C, keys KeyProvider, opts ...ParseOption) error

// ParseInsecure decodes the payload into dst WITHOUT verifying the signature
// or checking expiry. MUST NOT be used for any authorization decision —
// read-only inspection only (e.g. looking up a session by an expired token's
// "jti").
func ParseInsecure[C any](token string, dst *C) error

// ParseOption configures Parse, DecryptClaims and Middleware. Both the
// functional options below and a ParseOptions struct satisfy it and combine
// in one call (applied left to right; a later one wins), so a shared config
// can be declared once and reused, with per-call overrides:
//
//	var googleOpts = jwt.ParseOptions{
//		AllowedAlgorithms: []jwt.Algorithm{jwt.RS256, jwt.ES256},
//		Issuer:            "https://accounts.google.com",
//	}
//	err := jwt.Parse(ctx, tok, &claims, keys, googleOpts, jwt.WithAudience(clientID))
type ParseOption interface{ applyParse(*parseConfig) }

// ParseOptions is the reusable, declarative form of the same settings. A
// zero field imposes no constraint (Clock keeps the default). AllowedAlgorithms
// and RequiredClaims merge with any set via the functional options.
type ParseOptions struct {
	AllowedAlgorithms []Algorithm
	Issuer            string
	Audience          string
	RequiredType      string
	RequiredClaims    []string
	Leeway            time.Duration
	Clock             func() time.Time
}

func WithAllowedAlgorithms(algs ...Algorithm) ParseOption // required; RFC 8725 §3.1
func WithIssuer(iss string) ParseOption
func WithAudience(aud string) ParseOption
func WithRequiredType(typ string) ParseOption // RFC 8725 §3.11
func WithClock(now func() time.Time) ParseOption
func WithLeeway(d time.Duration) ParseOption // default 0; apps opt in
func WithRequiredClaims(names ...string) ParseOption

var (
	ErrInvalidSignature    = errors.New("jwt: invalid signature")
	ErrExpired             = errors.New("jwt: token expired")
	ErrNotYetValid         = errors.New("jwt: token not yet valid")
	ErrIssuerMismatch      = errors.New("jwt: issuer mismatch")
	ErrAudienceMismatch    = errors.New("jwt: audience mismatch")
	ErrAlgorithmNotAllowed = errors.New("jwt: algorithm not in allowlist")
	ErrNoAllowedAlgorithms = errors.New("jwt: WithAllowedAlgorithms is required")
	ErrMissingClaim        = errors.New("jwt: required claim missing")
	ErrMalformedToken      = errors.New("jwt: malformed token")
	ErrTypeMismatch        = errors.New("jwt: unexpected \"typ\" header")
)
```

Common single-key usage stays short despite the shared `KeyProvider`
abstraction (§0.9 in practice):

```go
keys := jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(pub, ""))
claims, err := jwt.Parse[MyClaims](ctx, token, keys, jwt.WithAllowedAlgorithms(jwt.EdDSA))
```

```go
// StaticKeyProvider adapts a single fixed Key — the common case where an
// application has exactly one signing key.
func StaticKeyProvider(k Key) KeyProvider

// MapKeyProvider adapts a fixed set of Keys, keyed by kid.
func MapKeyProvider(byKID map[string]Key) KeyProvider
```

### 5.2 Encryption (JWE, RFC 7516)

Both directions restricted to the modern, AEAD-based algorithm set — no
legacy-interop requirement was identified for either producing or consuming
encrypted tokens (§3.1). Like `Signer`/`Verifier`, `Encrypter`/`Decrypter` are
plain interfaces a caller can implement for a legacy algorithm if ever needed.

```go
type KeyAlgorithm string

const (
	ECDHES       KeyAlgorithm = "ECDH-ES"        // direct key agreement
	ECDHESA256KW KeyAlgorithm = "ECDH-ES+A256KW" // key agreement + wrapping
	RSAOAEP256   KeyAlgorithm = "RSA-OAEP-256"   // SHA-256 OAEP only
	A256KW       KeyAlgorithm = "A256KW"         // AES Key Wrap
	Direct       KeyAlgorithm = "dir"            // pre-shared symmetric CEK
)

type ContentAlgorithm string

const (
	A128GCM ContentAlgorithm = "A128GCM"
	A192GCM ContentAlgorithm = "A192GCM"
	A256GCM ContentAlgorithm = "A256GCM"
)

type Encrypter interface {
	KeyAlgorithm() KeyAlgorithm
	ContentAlgorithm() ContentAlgorithm
	KeyID() string
	Encrypt(plaintext []byte) (compact string, err error)
}

type Decrypter interface {
	KeyID() string
	Decrypt(ctx context.Context, compact string) (plaintext []byte, err error)
}

func NewRSAOAEP256Encrypter(pub *rsa.PublicKey, content ContentAlgorithm, kid string) (Encrypter, error)
func NewRSAOAEP256Decrypter(priv *rsa.PrivateKey, kid string) (Decrypter, error)

func NewECDHESEncrypter(pub *ecdsa.PublicKey, alg KeyAlgorithm, content ContentAlgorithm, kid string) (Encrypter, error)
func NewECDHESDecrypter(priv *ecdsa.PrivateKey, kid string) (Decrypter, error)

func NewA256KWEncrypter(kek []byte, content ContentAlgorithm, kid string) (Encrypter, error)
func NewA256KWDecrypter(kek []byte, kid string) (Decrypter, error)

func NewDirectEncrypter(cek []byte, content ContentAlgorithm, kid string) (Encrypter, error)
func NewDirectDecrypter(cek []byte, kid string) (Decrypter, error)

// EncryptClaims is the JWE analogue of Sign: JSON-marshal a claims value and
// encrypt it as a compact JWE.
func EncryptClaims[C any](claims C, enc Encrypter) (string, error)

// DecryptClaims is the JWE analogue of Parse: decrypt a compact JWE,
// validate the registered claims, and unmarshal the plaintext into dst (type
// inferred). The AEAD tag is verified before any plaintext is returned
// (§4.7) — a failure yields one generic error.
func DecryptClaims[C any](ctx context.Context, compact string, dst *C, dec Decrypter, opts ...ParseOption) error

var ErrDecryptionFailed = errors.New("jwt: decryption failed")
```

### 5.3 Keys & key resolution (JWK/JWKS, RFC 7517, RFC 7638)

```go
type KeyType string

const (
	KeyTypeRSA KeyType = "RSA"
	KeyTypeEC  KeyType = "EC"
	KeyTypeOKP KeyType = "OKP" // Ed25519 (RFC 8037)
	KeyTypeOct KeyType = "oct" // symmetric; internal use only, see warning below
)

// Key is a single JSON Web Key (RFC 7517 §4), covering every key type this
// library signs or verifies with. A Key with Kty == KeyTypeOct MUST NOT be
// serialized into a JWKS document served over HTTP — publishing a symmetric
// secret in a discoverable keyset is never correct — so MarshalJSON returns
// an error for KeyTypeOct, making that mistake impossible to ship by
// accident.
type Key struct {
	Kty KeyType
	Kid string
	Use string // "sig" | "enc"
	Alg string
	// n/e (RSA), crv/x/y (EC), crv/x (OKP), k (oct) fields are internal;
	// access parsed key material via PublicKey()/Secret().
}

func (k Key) PublicKey() (crypto.PublicKey, error) // RSA/EC/OKP only
func (k Key) Secret() ([]byte, error)               // oct only
func (k Key) Verifier() (Verifier, error)           // PublicKey/Secret + Alg -> Verifier

func FromRSAPublicKey(pub *rsa.PublicKey, kid string) Key
func FromECDSAPublicKey(pub *ecdsa.PublicKey, kid string) Key
func FromEd25519PublicKey(pub ed25519.PublicKey, kid string) Key
func FromHMACSecret(secret []byte, kid string) Key // Kty: oct

func ParseKey(data []byte) (Key, error)

// Thumbprint computes the RFC 7638 thumbprint of an already-parsed Key.
func Thumbprint(k Key, hash crypto.Hash) (string, error)

// ThumbprintBytes computes an RFC 7638-shaped thumbprint directly from raw
// key material the caller already has (e.g. an HMAC/oct secret), without
// requiring a parsed Key first. This is the identifier fed into
// RevocationStore for key-level revocation (§5.6), or into
// Confirmation.JWKThumbprint (§5.1).
func ThumbprintBytes(kty KeyType, raw []byte, hash crypto.Hash) (string, error)

// KeySet is a mutable, concurrency-safe KeyProvider (RFC 7517 §5's JWK Set) —
// the library's built-in in-memory implementation.
type KeySet struct{ /* unexported */ }

func NewKeySet(keys ...Key) *KeySet
func (s *KeySet) Add(k Key)
func (s *KeySet) Remove(kid string)
func (s *KeySet) Lookup(ctx context.Context, kid string) (Key, bool, error)
func (s *KeySet) Keys(ctx context.Context) ([]Key, error) // for serving as a JWKS document

// ParseKeySet parses a JWKS document into a ready-to-use KeySet.
func ParseKeySet(data []byte) (*KeySet, error)

// KeyFetcher retrieves and caches a remote JWKS document; it satisfies
// KeyProvider directly, so it plugs in wherever a KeySet would — avoiding
// the common hand-rolled-JWKS pitfalls of silently skipping non-RSA keys or
// falling back to "first key" when kid is absent. HTTPS-only by default,
// size-capped, honors HTTP caching headers when present.
type KeyFetcher struct{ /* unexported */ }

func NewKeyFetcher(uri string, opts ...FetcherOption) *KeyFetcher
func WithHTTPClient(c *http.Client) FetcherOption
func WithMinRefreshInterval(d time.Duration) FetcherOption
func WithMaxResponseBytes(n int64) FetcherOption

func (f *KeyFetcher) Lookup(ctx context.Context, kid string) (Key, bool, error) // satisfies KeyProvider
func (f *KeyFetcher) Refresh(ctx context.Context) error

// DiscoverJWKSURI resolves a JWKS URI from an OIDC/OAuth discovery document
// ("<issuer>/.well-known/openid-configuration", falling back to
// "<issuer>/.well-known/jwks.json").
func DiscoverJWKSURI(ctx context.Context, issuer string, client *http.Client) (string, error)
```

### 5.4 ID token claims (OIDC standard + provider-specific)

```go
// StandardClaims are the OpenID Connect Core 1.0 §5.1 standard claims,
// common across virtually every OIDC provider.
type StandardClaims struct {
	Name                string       `json:"name,omitempty"`
	GivenName           string       `json:"given_name,omitempty"`
	FamilyName          string       `json:"family_name,omitempty"`
	MiddleName          string       `json:"middle_name,omitempty"`
	Nickname            string       `json:"nickname,omitempty"`
	PreferredUsername   string       `json:"preferred_username,omitempty"`
	Profile             string       `json:"profile,omitempty"`
	Picture             string       `json:"picture,omitempty"`
	Website              string      `json:"website,omitempty"`
	Email               string       `json:"email,omitempty"`
	EmailVerified       *bool        `json:"email_verified,omitempty"`
	Gender              string       `json:"gender,omitempty"`
	Birthdate           string       `json:"birthdate,omitempty"`
	ZoneInfo            string       `json:"zoneinfo,omitempty"`
	Locale              string       `json:"locale,omitempty"`
	PhoneNumber         string       `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool        `json:"phone_number_verified,omitempty"`
	Address             *Address     `json:"address,omitempty"`
	UpdatedAt           *NumericDate `json:"updated_at,omitempty"`
	Nonce               string       `json:"nonce,omitempty"` // OIDC Core §2, replay protection
}

type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// GoogleClaims adds Google-specific ID token claims.
// https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload
type GoogleClaims struct {
	HostedDomain    string `json:"hd,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	AccessTokenHash string `json:"at_hash,omitempty"`
}

// OktaClaims adds Okta-specific ID token claims.
// https://developer.okta.com/docs/reference/api/oidc/#id-token
type OktaClaims struct {
	Version  string       `json:"ver,omitempty"`
	AuthTime *NumericDate `json:"auth_time,omitempty"`
	AMR      []string     `json:"amr,omitempty"`
	IDP      string       `json:"idp,omitempty"`
	Groups   []string     `json:"groups,omitempty"`
}

// EntraClaims adds Microsoft Entra ID (Azure AD) specific claims.
// https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
type EntraClaims struct {
	TenantID   string   `json:"tid,omitempty"`
	ObjectID   string   `json:"oid,omitempty"`
	UPN        string   `json:"upn,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	AppID      string   `json:"appid,omitempty"`
	Version    string   `json:"ver,omitempty"`
	UniqueName string   `json:"unique_name,omitempty"`
}

// Ready-made ID-token structs: RegisteredClaims + StandardClaims + a
// provider claim set, all embedded so encoding/json flattens them natively —
// no generics, no custom marshaler. Pass one straight to Parse, e.g.
// jwt.Parse[jwt.GoogleIDToken](...). For an unmodeled provider, declare the
// same shape with your own claim set in place of the third embed.
type GoogleIDToken struct {
	RegisteredClaims
	StandardClaims
	GoogleClaims
}

type OktaIDToken struct {
	RegisteredClaims
	StandardClaims
	OktaClaims
}

type EntraIDToken struct {
	RegisteredClaims
	StandardClaims
	EntraClaims
}
```

### 5.5 Opaque tokens (non-JWT bearer credentials)

Exactly two constructors (§0.8): one fresh-random, one string-derived.

```go
// OpaqueToken pairs a random or derived raw credential with its at-rest
// SHA-256 hash. Raw is handed to the client (e.g. in an HttpOnly cookie);
// only Hash is ever persisted.
type OpaqueToken struct {
	Raw  string
	Hash string
}

// NewOpaqueToken generates a fresh token: 32 bytes of crypto/rand,
// base64url-encoded.
func NewOpaqueToken() (OpaqueToken, error)

// DeriveOpaqueToken deterministically builds a token from a string the
// caller already holds, instead of a fresh random source.
func DeriveOpaqueToken(raw string) OpaqueToken

// Hash returns the SHA-256 hex digest of raw.
func Hash(raw string) string

// Equal compares a raw token against a stored hash in constant time.
func Equal(storedHash, raw string) bool

// TokenFamily identifies a lineage of rotated tokens sharing one logical
// session, so that presenting an already-rotated-away token can be detected
// as reuse and the whole family revoked — a common refresh-token-rotation
// pattern. The library defines the shape; storage is the caller's (see
// RevocationStore, §5.6, for the companion revocation state).
type TokenFamily struct{ ID string }

func NewTokenFamily() TokenFamily

// RotationResult is what a storage-backed rotation implementation should
// return; ReuseDetected signals the caller MUST revoke the entire family.
type RotationResult struct {
	Next          OpaqueToken
	ReuseDetected bool
}
```

### 5.6 Revocation

Generalized over identifier _namespace_: the same interface revokes a single
access token by `jti`, an entire signing key by its JWK thumbprint (`kid`),
or a refresh-token session by `TokenFamily.ID` — one interface instead of a
separate ad hoc revocation mechanism per identifier kind.

```go
type RevocationReason string

const (
	ReasonLogout         RevocationReason = "logout"
	ReasonKeyCompromised RevocationReason = "key_compromised" // identifier is a ThumbprintBytes-derived kid
	ReasonReuseDetected  RevocationReason = "reuse_detected"  // identifier is a TokenFamily.ID
	ReasonAdmin          RevocationReason = "admin_revoked"
)

// RevocationStore abstracts revocation-state storage. The library ships an
// in-memory implementation sufficient for a single-process deployment;
// real deployments should inject a shared store (Redis, a database) that
// satisfies this interface so revocation is visible across instances and
// survives restarts.
type RevocationStore interface {
	// Revoke marks id (a jti, a kid, or a TokenFamily.ID — the caller
	// decides the identifier namespace) as revoked until expiresAt.
	Revoke(ctx context.Context, id string, reason RevocationReason, expiresAt time.Time) error
	IsRevoked(ctx context.Context, id string) (bool, error)
}

// NewMemoryRevocationStore returns the library's built-in RevocationStore:
// an in-process, mutex-guarded map with lazy expiry sweep. Not persisted,
// not shared across instances — documented as single-process-only.
func NewMemoryRevocationStore() RevocationStore
```

### 5.7 HTTP bearer adapter (RFC 6750)

```go
// BearerToken extracts the token from an Authorization: Bearer header
// (RFC 6750 §2.1). Case-insensitive scheme match, single space separator.
func BearerToken(r *http.Request) (string, bool)

// Middleware verifies the request's bearer token with keys and opts, then
// stores the verified payload on the request context. On failure it writes
// an RFC 6750 §3-compliant 401 with a WWW-Authenticate header via
// WriteChallenge, then does not call next. It is not generic.
func Middleware(keys KeyProvider, opts ...ParseOption) func(http.Handler) http.Handler

// ClaimsFromContext unmarshals the payload Middleware stored into dst (type
// inferred). Returns ErrNoClaimsInContext if the request skipped Middleware.
func ClaimsFromContext[C any](ctx context.Context, dst *C) error

// WriteChallenge writes a WWW-Authenticate: Bearer header per RFC 6750 §3,
// mapping err to the realm/error/error_description parameters (e.g.
// ErrExpired -> error="invalid_token").
func WriteChallenge(w http.ResponseWriter, realm string, err error)
```

### 5.8 Access-token claims profile (RFC 9068)

```go
// AccessTokenClaims models the RFC 9068 JWT profile for OAuth 2.0 access
// tokens.
type AccessTokenClaims struct {
	RegisteredClaims
	ClientID     string       `json:"client_id"`
	Scope        string       `json:"scope,omitempty"`
	AuthTime     *NumericDate `json:"auth_time,omitempty"`
	ACR          string       `json:"acr,omitempty"`
	AMR          []string     `json:"amr,omitempty"`
	Groups       []string     `json:"groups,omitempty"`
	Roles        []string     `json:"roles,omitempty"`
	Entitlements []string     `json:"entitlements,omitempty"`
}

// AccessTokenType is the mandatory "typ" value per RFC 9068 §2, intended for
// use with WithRequiredType.
const AccessTokenType = "at+jwt"

// ValidateAccessTokenClaims checks the RFC 9068 §2 required-claims profile
// beyond what Parse already validates: iss, exp, aud, sub, client_id, iat
// MUST be present; jti SHOULD be present.
func ValidateAccessTokenClaims(claims AccessTokenClaims) error
```

### 5.9 Key material parsing (explicit per-encoding, `[]byte` only)

No auto-detection across encodings (§0.7): the caller PEM-decodes,
hex-decodes, or base64-decodes on their own and passes the resulting
`[]byte` to the matching parser. Every function is pure — no file I/O.

```go
// ParsePKCS8PrivateKey parses a DER-encoded PKCS#8 private key. Returns
// whichever concrete key type is embedded (*rsa.PrivateKey, *ecdsa.PrivateKey,
// ed25519.PrivateKey).
func ParsePKCS8PrivateKey(der []byte) (crypto.Signer, error)

// ParsePKCS1PrivateKey parses a DER-encoded PKCS#1 RSA private key.
func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error)

// ParseSEC1ECPrivateKey parses a DER-encoded SEC1 EC private key.
func ParseSEC1ECPrivateKey(der []byte) (*ecdsa.PrivateKey, error)

// ParseOpenSSHPrivateKey parses the OpenSSH private key wire format (its own
// binary framing — still just []byte, no PEM/base64/hex involved).
func ParseOpenSSHPrivateKey(raw []byte) (crypto.Signer, error)

// ParseEd25519PrivateKeySeed parses a raw 32-byte Ed25519 seed.
func ParseEd25519PrivateKeySeed(seed []byte) (ed25519.PrivateKey, error)

// ParseEd25519PrivateKeyExpanded parses a raw 64-byte expanded Ed25519 key.
func ParseEd25519PrivateKeyExpanded(raw []byte) (ed25519.PrivateKey, error)

// ParsePKIXPublicKey parses a DER-encoded PKIX public key (RSA or EC).
func ParsePKIXPublicKey(der []byte) (crypto.PublicKey, error)

// ParseEd25519PublicKey parses a raw 32-byte Ed25519 public key.
func ParseEd25519PublicKey(raw []byte) (ed25519.PublicKey, error)
```

---

## 6. API design conventions

These are the concrete conventions this library follows, drawn from Go's own
standard-library practice and the community-maintained
[Go Code Review Comments](https://go.dev/wiki/CodeReviewComments) and
[Google Go Style Guide](https://google.github.io/styleguide/go/) — the
existing, widely-adopted standards for writing a Go package meant to be
imported by other people, rather than an invented one-off style:

1. **No stutter.** Package identifier is `jwt`; exported names never repeat
   it (`jwt.Claims`, not `jwt.JWTClaims`; `jwt.Sign`, not `jwt.JWTSign`).
2. **Every exported identifier has a doc comment starting with its own
   name** (`// Sign encodes claims...`, `// Parse decodes...`), so `go doc`
   and godoc.org render a coherent package reference without extra tooling.
3. **Errors are sentinel values**, checked with `errors.Is`, named `Err*`,
   never bare strings a caller has to substring-match.
4. **Interfaces are minimal and defined where they're consumed** (`Signer`,
   `Verifier`, `KeyProvider`, `RevocationStore` are all one-to-two-method
   interfaces) — "accept interfaces, return concrete types," per Effective
   Go, so a caller only implements the handful of methods the library
   actually calls.
5. **`context.Context` is always the first parameter** on any function that
   can block on I/O (`Parse`, `Decrypt`, `KeyProvider.Lookup`,
   `RevocationStore.Revoke`) — never stored in a struct.
6. **Functional options (`With*`) for optional configuration** (`ParseOption`,
   `FetcherOption`), keeping constructors and `Parse`/`Sign` call sites short
   for the common case while remaining extensible without breaking changes.
7. **No global mutable state.** Every stateful type (`KeySet`, `KeyFetcher`,
   `MemoryRevocationStore`) is constructed explicitly and passed in, never a
   package-level singleton.
8. **No panics across the public API.** Every fallible function returns
   `error`; the only panics are programmer-error assertions inside the
   library's own tests.
9. **One package, many files, organized by concern** (§7), not by
   sub-package — consistent with decision §0.1. A consumer imports one path
   and gets everything; nothing forces juggling multiple import aliases for
   one coherent library the way `jwtkit/jwk`, `jwtkit/jwe`, `jwtkit/opaque`,
   etc. would have.
10. **Table-driven tests** for every algorithm/claim-validation matrix (one
    of the most consistent conventions across the Go standard library
    itself), keeping test code as unrepetitive as the production code.

One practical consequence worth naming: the package identifier `jwt` is also
used by the popular `golang-jwt/jwt` module. This is a normal, common Go
situation (many packages share a short identifier across different import
paths) and is resolved the ordinary way — a consumer that needs both in the
same file aliases one import (`import ghjwt "github.com/golang-jwt/jwt/v5"`).
It has no bearing on this library's own design and needs no special handling
here.

---

## 7. Repository plan

```
<repo root>/
├── .github/
│   └── workflows/
│       └── ci.yml            # go build/vet/test across a Go version matrix,
│                              # golangci-lint, govulncheck, gosec
├── jwt.go                    # Sign, Parse, ParseInsecure, ParseOption, errors
├── header.go                 # Header
├── claims.go                 # RegisteredClaims, Audience, NumericDate, Confirmation
├── alg_hmac.go                # HS256/384/512 Signer/Verifier
├── alg_rsa.go                 # PS*/RS* Signer/Verifier
├── alg_ecdsa.go                # ES256/384/512 Signer/Verifier
├── alg_eddsa.go                # EdDSA Signer/Verifier
├── jwe.go                     # EncryptClaims, DecryptClaims, Encrypter, Decrypter
├── jwe_rsa.go                  # RSA-OAEP-256
├── jwe_ecdh.go                 # ECDH-ES(+A256KW)
├── jwe_aeskw.go                # A256KW
├── jwe_direct.go                # dir
├── key.go                     # Key, KeyType, From*PublicKey, FromHMACSecret, ParseKey
├── keyset.go                   # KeySet, ParseKeySet
├── keyfetch.go                 # KeyFetcher, DiscoverJWKSURI
├── thumbprint.go                # Thumbprint, ThumbprintBytes
├── idtoken.go                  # StandardClaims, Address, Google/Okta/EntraClaims, Google/Okta/EntraIDToken
├── atclaims.go                  # AccessTokenClaims, ValidateAccessTokenClaims
├── opaque.go                   # OpaqueToken, NewOpaqueToken, DeriveOpaqueToken, Hash, Equal
├── rotation.go                  # TokenFamily, RotationResult
├── revoke.go                   # RevocationStore, MemoryRevocationStore, RevocationReason
├── httpauth.go                  # BearerToken, Middleware, ClaimsFromContext, WriteChallenge
├── keyparse.go                  # Parse*PrivateKey/PublicKey (§5.9)
├── doc.go                      # package-level doc comment
├── internal/
│   └── b64/                   # base64url helpers shared internally
├── examples/
│   ├── basic_hmac/
│   ├── verify_google_id_token/
│   ├── jwe_roundtrip/
│   └── refresh_rotation/
├── testdata/
│   ├── rfc7520/                # RFC 7520 JWS example vectors
│   ├── rfc7516/                # RFC 7516 JWE examples
│   └── idtoken_fixtures/       # static sample claim sets per provider, drawn
│                                # from each provider's public docs — no live
│                                # network calls needed to test claim shapes
├── go.mod
├── go.sum
├── README.md
├── SECURITY.md                # §4 of this document, kept in sync with the code
├── CHANGELOG.md
└── LICENSE                    # suggest MIT, matching typical personal-OSS Go libs
```

Notes:

- `internal/` guarantees the base64url helpers can't become an accidental
  public API surface that then can't be changed.
- No dependency on any web framework or database driver anywhere in the
  module; `go.mod` should have effectively zero third-party runtime
  dependencies beyond the Go standard library.
- No file performs file I/O, and none generates key material — both are
  entirely the caller's responsibility (§0.7).
- The module path itself (which GitHub org/repo, which import path) is a
  repository-setup decision, not a specification concern — left to whoever
  runs `go mod init` when the repo is created.

### 7.1 Versioning & release

- Start at `v0.x` (pre-1.0) while the API is validated against real call
  sites; tag `v1.0.0` once it has been in production use without needing a
  breaking change for a full release cycle.
- Semantic versioning from `v0.1.0` onward; `CHANGELOG.md` per
  [Keep a Changelog](https://keepachangelog.com/) conventions.
- CI gate for `v1.0.0` and later: no breaking change to any exported
  identifier without a major version bump (enforced by `apidiff` or similar).

### 7.2 Testing strategy

1. **RFC 7520 (JWS) and RFC 7516 (JWE) test vectors** run against every
   algorithm implementation to catch encoding mistakes (e.g. ECDSA signature
   format — JWA requires fixed-length concatenated `r‖s`, not ASN.1 DER).
2. **Cross-library interop tests**: tokens signed by this library must
   verify under `golang-jwt/jwt/v5` and `go-jose/go-jose/v4`, and vice versa,
   for every supported algorithm — both are widely used, so this is a
   realistic compatibility bar.
3. **Negative/security tests**, one per item in §4: alg-confusion attempt (an
   RS256 token verified with an HMAC key derived from the RSA public key's
   bytes), `alg: none` rejection, truncated/oversized token handling,
   expired/not-yet-valid/wrong-issuer/wrong-audience rejection, short-HMAC-key
   rejection, JWE tag-tamper rejection (fails closed, no partial plaintext).
4. **Fuzz tests** (`go test -fuzz`) on `Parse`, `DecryptClaims`, and
   `ParseKeySet`.
5. **Refresh rotation reuse-detection test**: rotate a token, replay the
   superseded one, assert `RotationResult.ReuseDetected` is usable to
   implement family-revocation behavior without the library itself touching
   storage.
6. **`KeyProvider`/`RevocationStore` conformance tests**: a shared test suite
   run against the built-in implementations (`KeySet`, `KeyFetcher`,
   `MemoryRevocationStore`) and against a minimal fake external
   implementation, proving `Parse`/revocation code paths work identically
   regardless of which implementation is injected (§0.6 in practice, not
   just in theory).
7. **Custom `Signer`/`Verifier` extensibility test**: a test-only RS256
   `Signer` implementing the interface directly (mirroring the §5.1 KMS
   example) round-trips through `Sign`/`Parse`, proving the "shortlist is
   built-ins only, not a closed system" guarantee actually holds.
8. **`idtoken` fixture tests**: static sample ID-token claim sets for Google,
   Okta, and Entra ID (drawn from each provider's public documentation, kept
   as `testdata/idtoken_fixtures/*.json`) round-tripped through
   `GoogleIDToken` / `OktaIDToken` / `EntraIDToken` to
   catch a provider changing its claim shape without needing live network
   access in CI.
