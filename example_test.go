package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"time"

	"github.com/NyeKo-ItL/jwt"
)

// The examples mirror the README snippets, so the documentation is compiled
// and, where the output is deterministic, checked.

type MyClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role,omitempty"`
}

func Example() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	signer, _ := jwt.NewEd25519Signer(priv, "key-1")
	token, _ := jwt.Sign(MyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  jwt.Audience{"https://api.example.com"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Role: "admin",
	}, signer)

	keys := jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(pub, "key-1"))

	var claims MyClaims

	err := jwt.Parse(context.Background(), token, &claims, keys,
		jwt.WithAllowedAlgorithms(jwt.Ed25519), // mandatory
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithAudience("https://api.example.com"),
	)
	fmt.Println(err, claims.Role)
	// Output: <nil> admin
}

func ExampleParseOptions() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := jwt.NewEd25519Signer(priv)
	token, _ := jwt.Sign(MyClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "https://auth.example.com", Audience: jwt.Audience{"orders"},
	}}, signer)
	keys := jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(pub))

	// Declare the shared policy once...
	apiOpts := jwt.ParseOptions{
		AllowedAlgorithms: []jwt.Algorithm{jwt.Ed25519},
		Issuer:            "https://auth.example.com",
	}

	// ...and add per-call settings.
	var claims MyClaims

	err := jwt.Parse(context.Background(), token, &claims, keys, apiOpts, jwt.WithAudience("orders"))
	fmt.Println(err)
	// Output: <nil>
}

func ExampleValidateAccessTokenClaims() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := jwt.NewEd25519Signer(priv)
	now := time.Now()

	// Authorization server side: RFC 9068 requires typ "at+jwt".
	token, _ := jwt.Sign(jwt.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "user-42",
			Audience:  jwt.Audience{"https://api.example.com"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        "at-1",
		},
		ClientID: "web-app",
		Scope:    "orders:read",
	}, signer, jwt.WithType(jwt.AccessTokenType))

	// Resource server side: every RFC 9068 §4 check.
	var at jwt.AccessTokenClaims

	err := jwt.Parse(context.Background(), token, &at, jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(pub)),
		jwt.WithAllowedAlgorithms(jwt.Ed25519),
		jwt.WithRequiredType(jwt.AccessTokenType),
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithAudience("https://api.example.com"),
	)
	if err == nil {
		err = jwt.ValidateAccessTokenClaims(at)
	}

	fmt.Println(err, slices.Contains(strings.Fields(at.Scope), "orders:read"))
	// Output: <nil> true
}

func ExampleDecryptClaims() {
	recipient, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	enc, _ := jwt.NewECDHESEncrypter(&recipient.PublicKey, jwt.ECDHESA256KW, jwt.A256GCM, "enc-1")
	compact, _ := jwt.EncryptClaims(MyClaims{Role: "billing"}, enc)

	dec, _ := jwt.NewECDHESDecrypter(recipient, "enc-1")

	var claims MyClaims

	err := jwt.DecryptClaims(context.Background(), compact, &claims, dec,
		jwt.WithAllowedKeyAlgorithms(jwt.ECDHESA256KW), // mandatory "alg" allowlist
		jwt.WithAllowedContentAlgorithms(jwt.A256GCM),  // mandatory "enc" allowlist
	)
	fmt.Println(err, claims.Role)
	// Output: <nil> billing
}

func ExampleMiddleware() {
	secret := []byte("0123456789abcdef0123456789abcdef")
	keys := jwt.StaticKeyProvider(jwt.FromHMACSecret(secret))

	handler := jwt.Middleware(keys,
		jwt.WithAllowedAlgorithms(jwt.HS256),
		jwt.WithAudience("https://api.example.com"),
		jwt.MiddlewareOptions{
			Realm: "api",
			OnError: func(r *http.Request, err error) {
				slog.DebugContext(r.Context(), "bearer authentication failed", "err", err)
			},
		},
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var claims MyClaims
		if err := jwt.ClaimsFromContext(r.Context(), &claims); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if claims.Role != "admin" {
			jwt.WriteInsufficientScope(w, "api", "admin")
			return
		}

		_, _ = fmt.Fprintln(w, "hello", claims.Subject)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	fmt.Println(rec.Code, rec.Header().Get("WWW-Authenticate"))
	// Output: 401 Bearer realm="api"
}

func ExampleNewKeyFetcher() {
	ctx := context.Background()

	// OpenID Connect Discovery: the returned issuer must match exactly.
	uri, err := jwt.DiscoverJWKSURI(ctx, "https://accounts.google.com", nil)
	if err != nil {
		return // errors.Is(err, jwt.ErrKeyFetch)
	}

	keys := jwt.NewKeyFetcher(uri, jwt.WithMaxCacheDuration(6*time.Hour))

	var idt jwt.GoogleIDToken

	err = jwt.Parse(ctx, "raw-id-token", &idt, keys,
		jwt.WithAllowedAlgorithms(jwt.RS256),
		jwt.WithIssuer("https://accounts.google.com"),
		jwt.WithAudience("1234987819200.apps.googleusercontent.com"), // your client ID
		jwt.WithRequiredClaims("sub", "iat"),
	)
	if err != nil {
		return
	}

	// Relying-party checks the library cannot do for you (OIDC Core §3.1.3.7):
	expectedNonce := "value-stored-in-the-session"
	if idt.Nonce != expectedNonce {
		return
	}
}

func ExampleKeySet_MarshalJSON() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	key := jwt.FromECDSAPublicKey(&priv.PublicKey, "2026-09")
	key.Use, key.Alg = "sig", string(jwt.ES256) // RFC 8725 §3.1: one key, one algorithm

	doc, _ := json.Marshal(jwt.NewKeySet(key))
	fmt.Println(strings.HasPrefix(string(doc), `{"keys":[{"kty":"EC","kid":"2026-09","use":"sig","alg":"ES256","crv":"P-256"`))

	// Symmetric keys can never be published.
	_, err := json.Marshal(jwt.NewKeySet(jwt.FromHMACSecret([]byte("0123456789abcdef0123456789abcdef"))))
	fmt.Println(errors.Is(err, jwt.ErrOctNotServable))
	// Output:
	// true
	// true
}
