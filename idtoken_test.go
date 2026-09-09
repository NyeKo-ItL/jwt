package jwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGoogleIDTokenRoundTrip(t *testing.T) {
	verified := true
	in := GoogleIDToken{
		RegisteredClaims: RegisteredClaims{
			Issuer:   "https://accounts.google.com",
			Subject:  "110169484474386276334",
			Audience: Audience{"1234.apps.googleusercontent.com"},
			IssuedAt: NewNumericDate(time.Unix(1_700_000_000, 0)),
		},
		StandardClaims: StandardClaims{Email: "jsmith@example.com", EmailVerified: &verified, Name: "John Smith"},
		GoogleClaims:   GoogleClaims{HostedDomain: "example.com", AuthorizedParty: "1234.apps.googleusercontent.com"},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	_ = json.Unmarshal(raw, &flat)
	for _, k := range []string{"iss", "sub", "aud", "email", "email_verified", "hd", "azp"} {
		if _, ok := flat[k]; !ok {
			t.Fatalf("missing %q in %s", k, raw)
		}
	}

	var out GoogleIDToken
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Subject != in.Subject || out.Email != in.Email || out.HostedDomain != in.HostedDomain {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

func TestOktaIDTokenParse(t *testing.T) {
	// Unmodeled members (custom_flag) are simply ignored — no Extra map.
	doc := `{"iss":"https://issuer","sub":"abc","email":"x@y.z","ver":"1.0",
		"amr":["pwd","mfa"],"custom_flag":true}`
	var tok OktaIDToken
	if err := json.Unmarshal([]byte(doc), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.Subject != "abc" || tok.Email != "x@y.z" || tok.Version != "1.0" || len(tok.AMR) != 2 {
		t.Fatalf("okta claims not parsed: %+v", tok)
	}
}

func TestEntraIDTokenFixture(t *testing.T) {
	doc := `{"iss":"https://login.microsoftonline.com/tid/v2.0","sub":"AAA","aud":"client",
		"tid":"22222222-2222-2222-2222-222222222222","oid":"33333333-3333-3333-3333-333333333333",
		"upn":"user@contoso.com","roles":["Admin"],"ver":"2.0"}`
	var tok EntraIDToken
	if err := json.Unmarshal([]byte(doc), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.TenantID == "" || tok.UPN != "user@contoso.com" || len(tok.Roles) != 1 {
		t.Fatalf("entra claims not parsed: %+v", tok)
	}
}

func TestValidateAccessTokenClaims(t *testing.T) {
	now := NewNumericDate(time.Unix(1_700_000_000, 0))
	full := AccessTokenClaims{
		Issuer:    "https://issuer",
		Subject:   "user-1",
		Audience:  Audience{"https://api"},
		ExpiresAt: now,
		IssuedAt:  now,
		ClientID:  "client-1",
		Scope:     "read write",
	}
	if err := ValidateAccessTokenClaims(full); err != nil {
		t.Fatalf("full claims rejected: %v", err)
	}

	bad := full
	bad.ClientID = ""
	bad.IssuedAt = nil
	err := ValidateAccessTokenClaims(bad)
	if err == nil {
		t.Fatal("expected error for missing client_id and iat")
	}
	if got := err.Error(); !strings.Contains(got, "client_id") || !strings.Contains(got, "iat") {
		t.Fatalf("error should name the missing claims: %q", got)
	}
}

func TestValidateAccessTokenClaimsNamesEveryMissingClaim(t *testing.T) {
	err := ValidateAccessTokenClaims(AccessTokenClaims{})
	if err == nil {
		t.Fatal("expected error for empty claims")
	}
	for _, want := range []string{"iss", "exp", "aud", "sub", "client_id", "iat"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestAccessTokenClaimsFlatJSON(t *testing.T) {
	raw, err := json.Marshal(AccessTokenClaims{
		Issuer:   "iss",
		ClientID: "c1",
		Roles:    []string{"a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	_ = json.Unmarshal(raw, &flat)
	if flat["iss"] != "iss" || flat["client_id"] != "c1" {
		t.Fatalf("flat = %s", raw)
	}
}
