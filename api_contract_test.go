package jwt_test

import (
	"context"
	"testing"

	"github.com/NyeKo-ItL/jwt"
)

type contractClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

func TestPublicJWSContract(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	signer, err := jwt.NewHMACSigner(jwt.HS256, key, "contract")
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwt.Sign(contractClaims{Role: "reader"}, signer)
	if err != nil {
		t.Fatal(err)
	}

	var got contractClaims

	provider := jwt.StaticKeyProvider(jwt.FromHMACSecret(key, "contract"))
	if err := jwt.Parse(context.Background(), token, &got, provider, jwt.WithAllowedAlgorithms(jwt.HS256)); err != nil {
		t.Fatal(err)
	}

	if got.Role != "reader" {
		t.Fatalf("Role = %q, want reader", got.Role)
	}
}

func TestPublicKeyParsingContract(t *testing.T) {
	key := jwt.FromHMACSecret([]byte("secret"), "contract")
	if key.Kid != "contract" || key.Kty != jwt.KeyTypeOct {
		t.Fatalf("unexpected public key shape: %+v", key)
	}
}
