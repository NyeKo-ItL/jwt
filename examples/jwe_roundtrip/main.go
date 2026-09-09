// Command jwe_roundtrip encrypts a claim set as a compact JWE with
// ECDH-ES+A256KW / A256GCM and decrypts it back.
package main

import (
	"context"
	"crypto/ecdsa"
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

	enc, err := jwt.NewECDHESEncrypter(&recipient.PublicKey, jwt.ECDHESA256KW, jwt.A256GCM, "kid-1")
	if err != nil {
		log.Fatal(err)
	}
	compact, err := jwt.EncryptClaims(payload{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.example",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "acct-9",
		Tier:      "gold",
	}, enc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("compact JWE:", compact)

	dec, err := jwt.NewECDHESDecrypter(recipient, "kid-1")
	if err != nil {
		log.Fatal(err)
	}
	var claims payload
	err = jwt.DecryptClaims(context.Background(), compact, &claims, dec,
		jwt.WithIssuer("https://issuer.example"),
	)
	if err != nil {
		log.Fatal(err) // any failure is a single generic error: fails closed
	}
	fmt.Printf("decrypted: account=%s tier=%s\n", claims.AccountID, claims.Tier)
}
