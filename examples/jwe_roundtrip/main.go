// Command jwe_roundtrip signs a claim set, encrypts the compact JWS with
// ECDH-ES+A256KW / A256GCM, then authenticates and decrypts both layers.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/NyeKo-ItL/jwt"
)

type payload struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	Tier      string `json:"tier"`
}

func main() {
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	verifyKey, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jwt.NewEd25519Signer(signKey, "sig-1")
	if err != nil {
		log.Fatal(err)
	}
	inner, err := jwt.Sign(payload{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.example",
			Audience:  jwt.Audience{"account-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "acct-9",
		Tier:      "gold",
	}, signer)
	if err != nil {
		log.Fatal(err)
	}

	enc, err := jwt.NewECDHESEncrypter(&recipient.PublicKey, jwt.ECDHESA256KW, jwt.A256GCM, "enc-1")
	if err != nil {
		log.Fatal(err)
	}
	compact, err := jwt.EncryptNestedJWT(inner, enc, jwt.WithJWEType("account+jwt"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("nested compact JWE:", compact)

	dec, err := jwt.NewECDHESDecrypter(recipient, "enc-1")
	if err != nil {
		log.Fatal(err)
	}

	var claims payload

	verificationKeys := jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(verifyKey, "sig-1"))
	err = jwt.DecryptNestedJWT(context.Background(), compact, &claims, dec, verificationKeys, jwt.NestedJWTPolicies{
		JWE: []jwt.ParseOption{
			jwt.WithAllowedKeyAlgorithms(jwt.ECDHESA256KW),
			jwt.WithAllowedContentAlgorithms(jwt.A256GCM),
			jwt.WithRequiredType("account+jwt"),
		},
		JWS: []jwt.ParseOption{
			jwt.WithAllowedAlgorithms(jwt.Ed25519),
			jwt.WithIssuer("https://issuer.example"),
			jwt.WithAudience("account-api"),
		},
	})
	if err != nil {
		log.Fatal(err) // any failure is a single generic error: fails closed
	}

	fmt.Printf("decrypted: account=%s tier=%s\n", claims.AccountID, claims.Tier)
}
