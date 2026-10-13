package jwt

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

func oidcHalfHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return b64.Encode(sum[:len(sum)/2])
}

func validV1IDTokenClaims() IDTokenClaims {
	now := NewNumericDate(time.Unix(1_700_000_000, 0))

	return IDTokenClaims{
		RegisteredClaims: RegisteredClaims{
			Issuer:    "https://issuer.example",
			Subject:   "subject-1",
			Audience:  Audience{"client-1", "api.example"},
			ExpiresAt: now,
			IssuedAt:  now,
		},
		StandardClaims:  StandardClaims{Nonce: "nonce-1"},
		AuthorizedParty: "client-1",
		AccessTokenHash: oidcHalfHash("access-token"),
		CodeHash:        oidcHalfHash("authorization-code"),
	}
}

func TestV1CoreValidateIDTokenForContext(t *testing.T) {
	claims := validV1IDTokenClaims()
	validation := IDTokenValidationContext{
		ClientID:          "client-1",
		TrustedAudiences:  []string{"api.example"},
		ExpectedNonce:     "nonce-1",
		RequireNonce:      true,
		AccessToken:       "access-token",
		AuthorizationCode: "authorization-code",
		SigningAlgorithm:  RS256,
	}

	if err := ValidateIDTokenForContext(claims, validation); err != nil {
		t.Fatalf("valid ID Token rejected: %v", err)
	}

	cases := map[string]func(*IDTokenClaims, *IDTokenValidationContext){
		"untrusted audience": func(c *IDTokenClaims, _ *IDTokenValidationContext) {
			c.Audience = append(c.Audience, "other.example")
		},
		"azp mismatch": func(c *IDTokenClaims, _ *IDTokenValidationContext) {
			c.AuthorizedParty = "other-client"
		},
		"nonce mismatch": func(_ *IDTokenClaims, v *IDTokenValidationContext) {
			v.ExpectedNonce = "other-nonce"
		},
		"access token hash mismatch": func(_ *IDTokenClaims, v *IDTokenValidationContext) {
			v.AccessToken = "other-access-token"
		},
		"missing code source": func(_ *IDTokenClaims, v *IDTokenValidationContext) {
			v.AuthorizationCode = ""
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			gotClaims, gotValidation := claims, validation
			gotClaims.Audience = append(Audience(nil), claims.Audience...)
			mutate(&gotClaims, &gotValidation)

			if err := ValidateIDTokenForContext(gotClaims, gotValidation); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestV1CoreIDTokenRequiredClaimsAndStringOrURI(t *testing.T) {
	claims := validV1IDTokenClaims()
	if err := ValidateIDTokenClaims(claims); err != nil {
		t.Fatal(err)
	}

	claims.ExpiresAt = nil
	if err := ValidateIDTokenClaims(claims); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("missing exp: %v", err)
	}

	for _, value := range []string{"https://valid.example/path", "plain-string", "urn:example:value"} {
		if err := ValidateStringOrURI(value); err != nil {
			t.Errorf("valid StringOrURI %q: %v", value, err)
		}
	}

	for _, value := range []string{":missing-scheme", "https://bad host", "urn:%zz"} {
		if err := ValidateStringOrURI(value); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("invalid StringOrURI %q: %v", value, err)
		}
	}
}

func TestV1CoreAccessTokenRequiresJTI(t *testing.T) {
	now := NewNumericDate(time.Unix(1_700_000_000, 0))
	claims := AccessTokenClaims{RegisteredClaims: RegisteredClaims{
		Issuer: "https://issuer.example", Subject: "subject", Audience: Audience{"api"},
		ExpiresAt: now, IssuedAt: now,
	}, ClientID: "client"}

	if err := ValidateAccessTokenClaims(claims); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("missing jti: %v", err)
	}

	claims.ID = "token-1"
	if err := ValidateAccessTokenClaims(claims); err != nil {
		t.Fatalf("complete access token: %v", err)
	}
}
