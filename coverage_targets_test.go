package jwt

import (
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCoverageAccessTokenValidationBranches(t *testing.T) {
	now := NewNumericDate(testNow())
	valid := AccessTokenClaims{RegisteredClaims: RegisteredClaims{
		Issuer: "https://issuer.example", Subject: "subject", Audience: Audience{"api"},
		ExpiresAt: now, IssuedAt: now, ID: "jti",
	}, ClientID: "client"}

	cases := []struct {
		name   string
		mutate func(*AccessTokenClaims)
		want   string
	}{
		{"invalid issuer", func(c *AccessTokenClaims) { c.Issuer = "1:bad" }, "iss:"},
		{"invalid subject", func(c *AccessTokenClaims) { c.Subject = ":bad" }, "sub:"},
		{"empty audience", func(c *AccessTokenClaims) { c.Audience = Audience{""} }, "aud[0]"},
		{"invalid audience", func(c *AccessTokenClaims) { c.Audience = Audience{"https://bad host"} }, "aud[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			tc.mutate(&claims)
			err := ValidateAccessTokenClaims(claims)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCoverageStringOrURIBranches(t *testing.T) {
	for _, value := range []string{"a://[::1"} {
		if err := ValidateStringOrURI(value); err == nil {
			t.Errorf("ValidateStringOrURI(%q) accepted invalid URI", value)
		}
	}
	for _, value := range []string{"a+b.c://ok", "https://example.com/a%20b", "plain"} {
		if err := ValidateStringOrURI(value); err != nil {
			t.Errorf("ValidateStringOrURI(%q): %v", value, err)
		}
	}
	for _, value := range []string{"a:%", "a:%0", "a:%zz", "a^:x"} {
		if !errors.Is(ValidateStringOrURI(value), ErrInvalidClaim) {
			t.Errorf("ValidateStringOrURI(%q) did not reject malformed value", value)
		}
	}
}

func TestCoverageIDTokenClaimsBranches(t *testing.T) {
	valid := validV1IDTokenClaims()
	cases := []struct {
		name   string
		mutate func(*IDTokenClaims)
		want   error
	}{
		{"missing required claims", func(c *IDTokenClaims) { *c = IDTokenClaims{} }, ErrMissingClaim},
		{"invalid issuer", func(c *IDTokenClaims) { c.Issuer = ":bad" }, ErrInvalidClaim},
		{"invalid subject", func(c *IDTokenClaims) { c.Subject = "1:bad" }, ErrInvalidClaim},
		{"empty audience", func(c *IDTokenClaims) { c.Audience = Audience{""} }, ErrInvalidClaim},
		{"invalid audience", func(c *IDTokenClaims) { c.Audience = Audience{"https://bad host"} }, ErrInvalidClaim},
		{"invalid azp syntax", func(c *IDTokenClaims) { c.AuthorizedParty = ":bad" }, ErrInvalidClaim},
		{"azp not audience", func(c *IDTokenClaims) { c.AuthorizedParty = "other" }, ErrInvalidClaim},
		{"invalid at hash", func(c *IDTokenClaims) { c.AccessTokenHash = "not valid!" }, ErrInvalidClaim},
		{"invalid code hash", func(c *IDTokenClaims) { c.CodeHash = "=" }, ErrInvalidClaim},
		{"empty amr", func(c *IDTokenClaims) { c.AMR = []string{"pwd", ""} }, ErrInvalidClaim},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			claims.Audience = append(Audience(nil), valid.Audience...)
			tc.mutate(&claims)
			if err := ValidateIDTokenClaims(claims); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCoverageIDTokenContextBranches(t *testing.T) {
	claims := validV1IDTokenClaims()
	base := IDTokenValidationContext{ClientID: "client-1", TrustedAudiences: []string{"api.example"}, SigningAlgorithm: RS256}
	cases := []struct {
		name   string
		mutate func(*IDTokenClaims, *IDTokenValidationContext)
	}{
		{"missing client", func(_ *IDTokenClaims, v *IDTokenValidationContext) { v.ClientID = "" }},
		{"client not audience", func(_ *IDTokenClaims, v *IDTokenValidationContext) { v.ClientID = "other" }},
		{"untrusted audience", func(c *IDTokenClaims, _ *IDTokenValidationContext) { c.Audience = append(c.Audience, "unknown") }},
		{"azp mismatch", func(c *IDTokenClaims, _ *IDTokenValidationContext) { c.AuthorizedParty = "api.example" }},
		{"multi audience missing matching azp", func(c *IDTokenClaims, _ *IDTokenValidationContext) { c.AuthorizedParty = "api.example" }},
		{"nonce mismatch", func(_ *IDTokenClaims, v *IDTokenValidationContext) { v.ExpectedNonce = "wrong" }},
		{"required nonce missing", func(_ *IDTokenClaims, v *IDTokenValidationContext) { v.RequireNonce = true }},
		{"unsupported hash algorithm", func(c *IDTokenClaims, v *IDTokenValidationContext) {
			c.AccessTokenHash = "x"
			v.AccessToken = "token"
			v.SigningAlgorithm = Algorithm("unknown")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, v := claims, base
			c.Audience = append(Audience(nil), claims.Audience...)
			tc.mutate(&c, &v)
			if err := ValidateIDTokenForContext(c, v); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestCoverageOIDCHashAlgorithms(t *testing.T) {
	for _, alg := range []Algorithm{HS256, HS384, HS512, EdDSA} {
		if _, ok := oidcHashAlgorithm(alg); !ok {
			t.Errorf("oidcHashAlgorithm(%q) not recognized", alg)
		}
	}
	if _, ok := oidcHashAlgorithm(Algorithm("none")); ok {
		t.Fatal("unknown algorithm recognized")
	}
	if err := validateOIDCHash("at_hash", "", "", RS256); err != nil {
		t.Fatal(err)
	}
	if err := validateOIDCHash("at_hash", "x", "", RS256); err == nil {
		t.Fatal("missing source value accepted")
	}
}

func TestCoverageThumbprintBranches(t *testing.T) {
	if _, err := ThumbprintBytes(KeyTypeOKP, []byte{1}, crypto.SHA256); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short OKP: %v", err)
	}
	for _, kty := range []KeyType{KeyTypeRSA, KeyTypeEC, KeyTypeOKP, KeyTypeOct, KeyType("other")} {
		if _, err := (Key{Kty: kty}).thumbprintInput(); !errors.Is(err, ErrMalformedKey) {
			t.Errorf("thumbprintInput(%q) error = %v", kty, err)
		}
	}
	if _, err := digestThumbprint("{}", crypto.MD4); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unavailable hash: %v", err)
	}
	if _, err := ParseKey([]byte(`{"kty":"oct","k":""}`)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("invalid parsed key: %v", err)
	}
}

func testNow() time.Time { return time.Unix(1_700_000_000, 0) }
