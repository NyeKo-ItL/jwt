package jwt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Provider fixture tests (spec §7.2.8): each provider's documented ID-token
// payload is signed as-is and parsed into its ready-made struct, so a claim
// whose documented shape does not fit the Go type fails here instead of in
// production.

func loadFixture(t *testing.T, name string) (payload json.RawMessage, claims map[string]any) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "idtoken_fixtures", name+".json")) //nolint:gosec // test-controlled fixture name
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Source  string          `json:"source"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Source == "" {
		t.Fatalf("fixture %s: %v", name, err)
	}

	if err := json.Unmarshal(doc.Payload, &claims); err != nil {
		t.Fatal(err)
	}

	return doc.Payload, claims
}

// parseFixture signs the fixture payload bytes verbatim and runs full Parse
// with the issuer, audience and a clock inside the token's lifetime.
func parseFixture[C any](t *testing.T, name string, dst *C) map[string]any {
	t.Helper()

	payload, claims := loadFixture(t, name)
	key, keys := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256","typ":"JWT"}`, string(payload))

	iat := int64(claims["iat"].(float64))

	err := Parse(ctx(), tok, dst, keys,
		WithAllowedAlgorithms(HS256),
		WithIssuer(claims["iss"].(string)),
		WithAudience(claims["aud"].(string)),
		WithRequiredClaims("iss", "sub", "aud", "exp", "iat"), // OIDC Core §2 REQUIRED claims
		WithClock(func() time.Time { return time.Unix(iat+60, 0) }))
	if err != nil {
		t.Fatalf("Parse %s fixture: %v", name, err)
	}

	return claims
}

func TestGoogleIDTokenFixture(t *testing.T) {
	var tok GoogleIDToken

	claims := parseFixture(t, "google", &tok)

	if tok.Subject != claims["sub"] || tok.Email != "jsmith@example.com" || tok.HostedDomain != "example.com" ||
		tok.AuthorizedParty != claims["azp"] || tok.AccessTokenHash != claims["at_hash"] || tok.Nonce != claims["nonce"] {
		t.Fatalf("google fields: %+v", tok)
	}

	// Google documents email_verified as the string "true".
	if tok.EmailVerified == nil || !*tok.EmailVerified {
		t.Fatalf("email_verified = %v", tok.EmailVerified)
	}
}

func TestOktaIDTokenFixture(t *testing.T) {
	var tok OktaIDToken

	claims := parseFixture(t, "okta", &tok)

	// Okta documents "ver" as the JSON number 1.
	if tok.Version != 1 || tok.ID != claims["jti"] || len(tok.AMR) != 1 || tok.AMR[0] != "pwd" ||
		tok.AuthTime == nil || tok.AuthTime.Unix() != 1449624026 {
		t.Fatalf("okta fields: %+v", tok)
	}

	if tok.Address == nil || tok.Address.Locality != "Los Angeles" || tok.MiddleName != "James" ||
		tok.UpdatedAt == nil || tok.UpdatedAt.Unix() != 1311280970 || tok.EmailVerified == nil || !*tok.EmailVerified {
		t.Fatalf("okta standard claims: %+v", tok.StandardClaims)
	}
}

func TestEntraIDTokenDocumentedClaims(t *testing.T) {
	var tok EntraIDToken

	claims := parseFixture(t, "entra", &tok)

	if tok.TenantID != claims["tid"] || tok.ObjectID != claims["oid"] || tok.Version != "2.0" ||
		len(tok.Roles) != 1 || tok.PreferredUsername != "AbeLi@microsoft.com" || tok.NotBefore == nil {
		t.Fatalf("entra fields: %+v", tok)
	}

	if tok.IdentityProvider != claims["idp"] || tok.SessionID != claims["sid"] || tok.TokenID != claims["uti"] {
		t.Fatalf("entra idp/sid/uti: %+v", tok.EntraClaims)
	}
}

func TestProviderFixturesRoundTrip(t *testing.T) {
	// Every claim a provider struct models survives Marshal → Parse with the
	// same JSON member name (no silent renames or type drift).
	for name, dst := range map[string]any{"google": &GoogleIDToken{}, "okta": &OktaIDToken{}, "entra": &EntraIDToken{}} {
		t.Run(name, func(t *testing.T) {
			payload, claims := loadFixture(t, name)
			if err := decodeObject(payload, dst); err != nil {
				t.Fatal(err)
			}

			out, err := json.Marshal(dst)
			if err != nil {
				t.Fatal(err)
			}

			var back map[string]any
			if err := json.Unmarshal(out, &back); err != nil {
				t.Fatal(err)
			}

			for k, v := range back {
				orig, ok := claims[k]
				if !ok {
					t.Errorf("marshaled member %q was not in the fixture", k)
					continue
				}

				if name == "google" && k == "email_verified" {
					continue // normalized from the documented "true" string to JSON true
				}

				a, _ := json.Marshal(orig)
				b, _ := json.Marshal(v)

				if string(a) != string(b) {
					t.Errorf("member %q: fixture %s, round trip %s", k, a, b)
				}
			}
		})
	}
}

func TestBoolAcceptsOIDCProviderForms(t *testing.T) {
	for in, want := range map[string]bool{`true`: true, `false`: false, `"true"`: true, `"false"`: false} {
		var b Bool
		if err := b.UnmarshalJSON([]byte(in)); err != nil || bool(b) != want {
			t.Errorf("Bool.UnmarshalJSON(%s) = %v, %v", in, b, err)
		}
	}

	for _, in := range []string{`"TRUE"`, `"True"`, `"yes"`, `1`, `0`, `"1"`, `""`, `null`, `[]`} {
		var b Bool
		if err := b.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("Bool.UnmarshalJSON(%s) accepted", in)
		}
	}

	out, _ := json.Marshal(struct {
		V *Bool `json:"v"`
	}{V: new(Bool(true))})
	if string(out) != `{"v":true}` {
		t.Fatalf("Bool marshals as %s", out)
	}
}
