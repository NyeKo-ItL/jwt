package jwt

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHeaderMinimalMarshal(t *testing.T) {
	raw, err := json.Marshal(Header{Algorithm: HS256})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"alg":"HS256"}` {
		t.Fatalf("minimal header = %s", raw)
	}
}

func TestHeaderFullRoundTrip(t *testing.T) {
	in := Header{
		Algorithm:      ES256,
		Type:           "JWT",
		ContentType:    "example",
		KeyID:          "k1",
		JWKSetURL:      "https://issuer/jwks",
		X509URL:        "https://issuer/x5u",
		X509CertChain:  []string{"MIIB", "MIIC"},
		X509CertSHA1:   "deadbeef",
		X509CertSHA256: "cafebabe",
		Critical:       []string{"exp"},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"x5t#S256":"cafebabe"`) {
		t.Fatalf("x5t#S256 tag not emitted: %s", raw)
	}
	var out Header
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	reRaw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(reRaw) != string(raw) {
		t.Fatalf("header round trip changed bytes:\n %s\n %s", raw, reRaw)
	}
}
