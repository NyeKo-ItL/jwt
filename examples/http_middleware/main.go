// Command http_middleware protects an HTTP handler with jwt.Middleware and
// exercises it with an in-process request.
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/NyeKo-ItL/jwt"
)

type apiClaims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope"`
}

func main() {
	secret := []byte("a-32-byte-hmac-secret-for-hs256!!")
	signer, err := jwt.NewHMACSigner(jwt.HS256, secret, "k1")
	if err != nil {
		log.Fatal(err)
	}
	keys := jwt.StaticKeyProvider(jwt.FromHMACSecret(secret, "k1"))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var claims apiClaims
		if err := jwt.ClaimsFromContext(r.Context(), &claims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintf(w, "hello %s (scope %q)\n", claims.Subject, claims.Scope)
	})
	handler := jwt.Middleware(keys,
		jwt.WithAllowedAlgorithms(jwt.HS256),
		jwt.WithAudience("https://api.example"),
	)(protected)

	token, _ := jwt.Sign(apiClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-7",
			Audience:  jwt.Audience{"https://api.example"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
		Scope: "read",
	}, signer)

	// authorized request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	fmt.Printf("with token:   %d %s", rec.Code, rec.Body.String())

	// missing credentials
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	fmt.Printf("no token:     %d  WWW-Authenticate: %s\n", rec.Code, rec.Header().Get("WWW-Authenticate"))
}
