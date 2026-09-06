# jwt

A single-package JWT / JOSE library for Go: JWS signing and verification, JWE
encryption, JWK / JWKS handling with pluggable key resolution, OIDC and
provider-specific claim sets, opaque-token utilities, revocation, and a thin
HTTP bearer adapter — one import path, no third-party runtime dependencies.

See [`spec.md`](spec.md) for the full design and RFC-compliance matrix.

## Install

```sh
go get github.com/NyeKo-ItL/jwt
```

## At a glance

### Sign and verify a JWS

```go
signer, _ := jwt.NewEd25519Signer(priv, "key-1")
token, _ := jwt.Sign(jwt.Claims[MyClaims]{
    RegisteredClaims: jwt.RegisteredClaims{Issuer: "me", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
    Custom:           MyClaims{Role: "admin"},
}, signer)

keys := jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(pub, "key-1"))
claims, err := jwt.Parse[MyClaims](ctx, token, keys,
    jwt.WithAllowedAlgorithms(jwt.EdDSA),
    jwt.WithIssuer("me"),
)
```

`jwt.WithAllowedAlgorithms` is mandatory (RFC 8725 §3.1); `alg: none` is never
representable in either direction.

### Verify third-party ID tokens over JWKS

```go
uri, _ := jwt.DiscoverJWKSURI(ctx, "https://accounts.google.com", nil)
keys := jwt.NewKeyFetcher(uri)
idt, err := jwt.Parse[jwt.IDToken[jwt.GoogleClaims]](ctx, raw, keys,
    jwt.WithAllowedAlgorithms(jwt.RS256),
    jwt.WithAudience(clientID),
)
```

### Encrypt claims as a JWE

```go
enc, _ := jwt.NewECDHESEncrypter(recipientPub, jwt.ECDHESA256KW, jwt.A256GCM, "")
compact, _ := jwt.EncryptClaims(claims, enc)

dec, _ := jwt.NewECDHESDecrypter(recipientPriv, "")
out, err := jwt.DecryptClaims[MyClaims](ctx, compact, dec)
```

## Scope

In: JWS (HMAC, RSA-PSS sign / PKCS#1 v1.5 verify, ECDSA, Ed25519), JWE
(RSA-OAEP-256, ECDH-ES(+A256KW), A256KW, dir with AES-GCM), JWK/JWKS,
RFC 7638 thumbprints, RFC 9068 access-token claims, opaque tokens, refresh
rotation shapes, revocation, RFC 6750 bearer extraction.

Out: OAuth 2.x authorization server, OIDC relying-party flow orchestration,
file I/O, key generation. See `spec.md` §2.2.

## License

MIT — see [LICENSE](LICENSE).
