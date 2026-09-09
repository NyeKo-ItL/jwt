package jwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIDTokenGoogleRoundTrip(t *testing.T) {
	verified := true
	in := IDToken[GoogleClaims]{
		Issuer:        "https://accounts.google.com",
		Subject:       "110169484474386276334",
		Audience:      Audience{"1234.apps.googleusercontent.com"},
		IssuedAt:      NewNumericDate(time.Unix(1_700_000_000, 0)),
		Email:         "jsmith@example.com",
		EmailVerified: &verified,
		Name:          "John Smith",
		Provider:      GoogleClaims{HostedDomain: "example.com", AuthorizedParty: "1234.apps.googleusercontent.com"},
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

	var out IDToken[GoogleClaims]
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Subject != in.Subject || out.Email != in.Email || out.Provider != in.Provider {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	if len(out.Extra) != 0 {
		t.Fatalf("unexpected Extra: %v", out.Extra)
	}
}

func TestIDTokenExtraCapturesUnknownClaims(t *testing.T) {
	doc := `{
		"iss": "https://issuer",
		"sub": "abc",
		"email": "x@y.z",
		"ver": "1.0",
		"custom_flag": true,
		"tenant_region": "eu"
	}`
	var tok IDToken[OktaClaims]
	if err := json.Unmarshal([]byte(doc), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.Provider.Version != "1.0" {
		t.Fatalf("provider ver = %q", tok.Provider.Version)
	}
	if tok.Extra["custom_flag"] != true || tok.Extra["tenant_region"] != "eu" {
		t.Fatalf("Extra = %v", tok.Extra)
	}
	if _, leaked := tok.Extra["email"]; leaked {
		t.Fatal("modeled standard claim leaked into Extra")
	}

	// Extra survives a re-marshal, modeled claims still win.
	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	if back["custom_flag"] != true || back["ver"] != "1.0" || back["email"] != "x@y.z" {
		t.Fatalf("re-marshal lost data: %s", raw)
	}
}

func TestIDTokenEntraFixture(t *testing.T) {
	doc := `{"iss":"https://login.microsoftonline.com/tid/v2.0","sub":"AAA","aud":"client",
		"tid":"22222222-2222-2222-2222-222222222222","oid":"33333333-3333-3333-3333-333333333333",
		"upn":"user@contoso.com","roles":["Admin"],"ver":"2.0"}`
	var tok IDToken[EntraClaims]
	if err := json.Unmarshal([]byte(doc), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.Provider.TenantID == "" || tok.Provider.UPN != "user@contoso.com" || len(tok.Provider.Roles) != 1 {
		t.Fatalf("entra claims not parsed: %+v", tok.Provider)
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

func TestIDTokenMarshalErrors(t *testing.T) {
	// un-marshalable Extra value
	tok := IDToken[GoogleClaims]{Extra: map[string]any{"bad": make(chan int)}}
	if _, err := json.Marshal(tok); err == nil {
		t.Fatal("expected error for un-marshalable Extra value")
	}
	// a non-object Provider cannot be merged
	if _, err := json.Marshal(IDToken[int]{Provider: 7}); err == nil {
		t.Fatal("expected error for non-object Provider")
	}
}

func TestIDTokenUnmarshalErrors(t *testing.T) {
	var a IDToken[GoogleClaims]
	if err := a.UnmarshalJSON([]byte(`[1,2,3]`)); err == nil {
		t.Fatal("expected error unmarshaling a JSON array")
	}
	var b IDToken[int]
	if err := b.UnmarshalJSON([]byte(`{"iss":"x"}`)); err == nil {
		t.Fatal("expected error: Provider int cannot receive an object")
	}
}

func TestJSONFieldNames(t *testing.T) {
	if jsonFieldNames(nil) != nil {
		t.Fatal("nil should yield no names")
	}
	if jsonFieldNames(5) != nil {
		t.Fatal("non-struct should yield no names")
	}
	type inner struct {
		A string `json:"a"`
	}
	type sample struct {
		inner
		Tagged   string `json:"tagged"`
		Untagged string
		Skipped  string `json:"-"`
		hidden   string //nolint:unused
	}
	got := jsonFieldNames(&sample{})
	want := map[string]bool{"a": true, "tagged": true, "Untagged": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want keys %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected field name %q in %v", n, got)
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

func TestIDTokenMarshalWithNilProvider(t *testing.T) {
	// A Provider that marshals to JSON null must be a no-op in the merge.
	raw, err := json.Marshal(IDToken[[]string]{RegisteredClaims: RegisteredClaims{Issuer: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"iss":"x"}` {
		t.Fatalf("raw = %s", raw)
	}
}
