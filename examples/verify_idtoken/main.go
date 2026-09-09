// Command verify_idtoken shows the JWKS + provider-claims path: an OpenID
// provider signs an ID token with ES256 and publishes its public key in a
// JWK Set; a relying party verifies it as a jwt.GoogleIDToken. The JWKS is
// kept in-process so the example runs offline — against a real provider
// swap jwt.ParseKeySet for jwt.NewKeyFetcher(uri).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/NyeKo-ItL/jwt"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	const kid = "2024-06"

	signer, err := jwt.NewECDSASigner(jwt.ES256, priv, kid)
	if err != nil {
		log.Fatal(err)
	}

	verified := true
	idToken, err := jwt.Sign(jwt.GoogleIDToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://accounts.google.com",
			Subject:   "110169484474386276334",
			Audience:  jwt.Audience{"1234567890.apps.googleusercontent.com"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		StandardClaims: jwt.StandardClaims{Email: "jsmith@example.com", EmailVerified: &verified, Name: "John Smith"},
		GoogleClaims:   jwt.GoogleClaims{HostedDomain: "example.com"},
	}, signer)
	if err != nil {
		log.Fatal(err)
	}

	// The provider's published JWKS document.
	jwks, _ := json.Marshal(jwt.NewKeySet(jwt.FromECDSAPublicKey(&priv.PublicKey, kid)))
	keys, err := jwt.ParseKeySet(jwks)
	if err != nil {
		log.Fatal(err)
	}

	var claims jwt.GoogleIDToken
	err = jwt.Parse(context.Background(), idToken, &claims, keys,
		jwt.WithAllowedAlgorithms(jwt.ES256, jwt.RS256), // Google normally uses RS256
		jwt.WithIssuer("https://accounts.google.com"),
		jwt.WithAudience("1234567890.apps.googleusercontent.com"),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("verified ID token: sub=%s email=%s hd=%s\n",
		claims.Subject, claims.Email, claims.HostedDomain)
}
