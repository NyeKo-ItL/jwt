# Test data

Everything here is **public, non-secret** material taken from standards and
provider documentation. It exists so that tests can check this library against
independent known answers, not just against itself (spec §7.2).

| Path | Content | Source |
|---|---|---|
| `vectors/jose.json` | JWS vectors (HS256, RS256, ES256, ES512, PS384), the unsecured `alg: none` example, and the `dir` + `A128GCM` JWE vector | [RFC 7515 Appendix A](https://www.rfc-editor.org/rfc/rfc7515#appendix-A), [RFC 7520 §3–§4, §5.6](https://www.rfc-editor.org/rfc/rfc7520) |
| `idtoken_fixtures/google.json` | Example ID token payload, verbatim | [Google OpenID Connect docs](https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload) |
| `idtoken_fixtures/okta.json` | Example ID token payload, verbatim (domain placeholder filled in) | [Okta OAuth 2.0 / OIDC overview](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview/) |
| `idtoken_fixtures/entra.json` | v2.0 payload built from the documented claim table | [Microsoft Entra ID token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference) |

Vectors that are short enough to read inline live in the tests themselves:
RFC 7518 Appendix C (ECDH-ES), RFC 8037 Appendix A (Ed25519, thumbprint),
RFC 7638 §3.1 (thumbprint) and RFC 3394 §4.3/§4.6 (AES Key Wrap).

JWK entries keep only the **public** members (`kty`, `kid`, `use`, `alg`,
`crv`, `x`, `y`, `n`, `e`) plus the symmetric `k` used by the HMAC and `dir`
examples. The RFC private members are left out.

Only vectors for algorithms this library implements are included. RFC 7520
examples for RSA1_5, RSA-OAEP (SHA-1), PBES2, AES-CBC-HMAC, A128KW, AES-GCM Key
Wrap, compression and JSON serialization are out of scope (see `COMPLIANCE.md`).
