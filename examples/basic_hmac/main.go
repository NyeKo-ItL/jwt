// Command basic_hmac signs a JWT with HS256 and verifies it back.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/NyeKo-ItL/jwt"
)

type sessionClaims struct {
	Role string `json:"role"`
}

func main() {
	secret := make([]byte, 32) // HS256 needs >= 32 bytes
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}

	signer, err := jwt.NewHMACSigner(jwt.HS256, secret, "sess-key-1")
	if err != nil {
		log.Fatal(err)
	}

	token, err := jwt.Sign(jwt.Claims[sessionClaims]{
		Issuer:    "https://auth.example",
		Subject:   "user-42",
		Audience:  jwt.Audience{"https://api.example"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Custom:    sessionClaims{Role: "admin"},
	}, signer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", token)

	keys := jwt.StaticKeyProvider(jwt.FromHMACSecret(secret, "sess-key-1"))
	claims, err := jwt.Parse[sessionClaims](context.Background(), token, keys,
		jwt.WithAllowedAlgorithms(jwt.HS256),
		jwt.WithIssuer("https://auth.example"),
		jwt.WithAudience("https://api.example"),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("verified: sub=%s role=%s\n", claims.Subject, claims.Custom.Role)
}
