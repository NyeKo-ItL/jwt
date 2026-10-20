package jwt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/NyeKo-ItL/jwt"
)

// RFC 9999 §5.1, §5.6 and §5.7 examples.
const (
	rfc9999Record     = `["application/vnd.example.rats-conceptual-msg","I0faVQ"]`
	rfc9999Collection = `{
		"__cmwc_t": "tag:example.com,2024:another-composite-attester",
		"attester A": ["application/eat-ucs+json", "e30K", 4],
		"attester B": ["application/eat-ucs+cbor", "oA", 4]
	}`
)

func TestParseCMWRFC9999Record(t *testing.T) {
	cmw, err := jwt.ParseCMW([]byte(rfc9999Record))
	if err != nil {
		t.Fatal(err)
	}

	if cmw.Record == nil || cmw.Collection != nil {
		t.Fatalf("want a record, got %+v", cmw)
	}

	if cmw.Record.Type != "application/vnd.example.rats-conceptual-msg" {
		t.Fatalf("Type = %q", cmw.Record.Type)
	}

	if !bytes.Equal(cmw.Record.Value, []byte{0x23, 0x47, 0xda, 0x55}) {
		t.Fatalf("Value = %x", cmw.Record.Value)
	}

	if cmw.Record.Indicator != nil {
		t.Fatalf("Indicator = %v, want nil", *cmw.Record.Indicator)
	}
}

func TestParseCMWRFC9999Collection(t *testing.T) {
	cmw, err := jwt.ParseCMW([]byte(rfc9999Collection))
	if err != nil {
		t.Fatal(err)
	}

	col := cmw.Collection
	if col == nil || cmw.Record != nil {
		t.Fatalf("want a collection, got %+v", cmw)
	}

	if col.Type != "tag:example.com,2024:another-composite-attester" || len(col.Members) != 2 {
		t.Fatalf("collection = %+v", col)
	}

	a := col.Members["attester A"].Record
	if a == nil || string(a.Value) != "{}\n" || a.Indicator == nil || *a.Indicator != jwt.CMWEvidence {
		t.Fatalf("attester A = %+v", a)
	}
}

func TestCMWClaimRoundTripThroughJWT(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	signer, err := jwt.NewHMACSigner(jwt.HS256, key, "cmw")
	if err != nil {
		t.Fatal(err)
	}

	var cmw jwt.CMW
	if err := json.Unmarshal([]byte(rfc9999Collection), &cmw); err != nil {
		t.Fatal(err)
	}

	token, err := jwt.Sign(jwt.CMWClaims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "evidence collection daemon"},
		CMW:              &cmw,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}

	var got jwt.CMWClaims

	provider := jwt.StaticKeyProvider(jwt.FromHMACSecret(key, "cmw"))
	if err := jwt.Parse(context.Background(), token, &got, provider, jwt.WithAllowedAlgorithms(jwt.HS256)); err != nil {
		t.Fatal(err)
	}

	if got.CMW == nil || got.CMW.Collection == nil || len(got.CMW.Collection.Members) != 2 {
		t.Fatalf("CMW = %+v", got.CMW)
	}

	if jwt.CMWClaimName != "cmw" {
		t.Fatalf("CMWClaimName = %q", jwt.CMWClaimName)
	}
}

func TestCMWMarshalRoundTrip(t *testing.T) {
	for _, in := range []string{rfc9999Record, rfc9999Collection, `{"a":{"b":["text/plain","YQ",31]}}`, `{"__cmwc_t":"2.5.4.3","x":["a/b;charset=utf-8","YQ"]}`} {
		first, err := jwt.ParseCMW([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}

		out, err := json.Marshal(first)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}

		second, err := jwt.ParseCMW(out)
		if err != nil {
			t.Fatalf("%s: re-parse %s: %v", in, out, err)
		}

		again, _ := json.Marshal(second)
		if !bytes.Equal(out, again) {
			t.Fatalf("marshal not stable: %s vs %s", out, again)
		}
	}
}

func TestParseCMWRejects(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 20) + `["a/b","YQ"]` + strings.Repeat(`}`, 20)

	tests := map[string]string{
		"empty":                   ``,
		"whitespace only":         "  \n",
		"scalar":                  `"text/plain"`,
		"null":                    `null`,
		"record too short":        `["text/plain"]`,
		"record too long":         `["text/plain","YQ",1,2]`,
		"type not string":         `[1,"YQ"]`,
		"type without slash":      `["plain","YQ"]`,
		"type empty subtype":      `["text/","YQ"]`,
		"type bad parameter":      `["text/plain;charset","YQ"]`,
		"value not string":        `["text/plain",1]`,
		"value empty":             `["text/plain",""]`,
		"value padded":            `["text/plain","YQ=="]`,
		"value standard base64":   `["text/plain","a+b/"]`,
		"value bad length":        `["text/plain","Y"]`,
		"indicator negative":      `["text/plain","YQ",-1]`,
		"indicator fraction":      `["text/plain","YQ",1.5]`,
		"indicator too big":       `["text/plain","YQ",4294967296]`,
		"indicator string":        `["text/plain","YQ","4"]`,
		"record bad json":         `["text/plain",`,
		"collection empty":        `{}`,
		"collection only type":    `{"__cmwc_t":"2.5.4.3"}`,
		"collection type number":  `{"__cmwc_t":1,"a":["a/b","YQ"]}`,
		"collection type bare":    `{"__cmwc_t":"not a uri","a":["a/b","YQ"]}`,
		"collection type bad oid": `{"__cmwc_t":"1.01","a":["a/b","YQ"]}`,
		"collection member bad":   `{"a":"text/plain"}`,
		"collection nested bad":   `{"a":{"b":["x","YQ"]}}`,
		"collection duplicate":    `{"a":["a/b","YQ"],"a":["a/b","YQ"]}`,
		"collection too deep":     deep,
		"collection bad json":     `{"a":`,
	}

	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := jwt.ParseCMW([]byte(in))
			if !errors.Is(err, jwt.ErrInvalidClaim) {
				t.Fatalf("ParseCMW(%s) = %v, want ErrInvalidClaim", in, err)
			}
		})
	}
}

func TestParseCMWAcceptsCollectionTypeForms(t *testing.T) {
	for _, typ := range []string{"2.5.4.3", "0.0", "tag:example.com,2024:x", "https://example.com/c"} {
		in := `{"__cmwc_t":"` + typ + `","a":["a/b","YQ"]}`
		if _, err := jwt.ParseCMW([]byte(in)); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
}

func TestCMWValidateAndMarshalReject(t *testing.T) {
	record := &jwt.CMWRecord{Type: "text/plain", Value: []byte("x")}
	member := jwt.CMW{Record: record}

	bad := map[string]jwt.CMW{
		"empty":          {},
		"both":           {Record: record, Collection: &jwt.CMWCollection{Members: map[string]jwt.CMW{"a": member}}},
		"bad media type": {Record: &jwt.CMWRecord{Type: "nope"}},
		"no members":     {Collection: &jwt.CMWCollection{}},
		"bad type":       {Collection: &jwt.CMWCollection{Type: "nope", Members: map[string]jwt.CMW{"a": member}}},
		"reserved label": {Collection: &jwt.CMWCollection{Members: map[string]jwt.CMW{"__cmwc_t": member}}},
		"bad member":     {Collection: &jwt.CMWCollection{Members: map[string]jwt.CMW{"a": {}}}},
		"too deep":       deepCMW(20, member),
	}

	for name, cmw := range bad {
		t.Run(name, func(t *testing.T) {
			if err := cmw.Validate(); !errors.Is(err, jwt.ErrInvalidClaim) {
				t.Fatalf("Validate = %v", err)
			}

			if _, err := json.Marshal(cmw); !errors.Is(err, jwt.ErrInvalidClaim) {
				t.Fatalf("Marshal = %v", err)
			}
		})
	}

	var into jwt.CMW
	if err := json.Unmarshal([]byte(`{}`), &into); !errors.Is(err, jwt.ErrInvalidClaim) {
		t.Fatalf("Unmarshal = %v", err)
	}
}

func deepCMW(levels int, leaf jwt.CMW) jwt.CMW {
	cmw := leaf
	for range levels {
		cmw = jwt.CMW{Collection: &jwt.CMWCollection{Members: map[string]jwt.CMW{"a": cmw}}}
	}

	return cmw
}

func TestCMWIndicatorBits(t *testing.T) {
	want := map[jwt.CMWIndicator]uint32{
		jwt.CMWReferenceValues: 1, jwt.CMWEndorsements: 2, jwt.CMWEvidence: 4,
		jwt.CMWAttestationResults: 8, jwt.CMWAppraisalPolicy: 16,
	}
	for ind, bits := range want {
		if uint32(ind) != bits {
			t.Errorf("indicator %d != %d", ind, bits)
		}
	}
}

func FuzzParseCMW(f *testing.F) {
	for _, seed := range []string{rfc9999Record, rfc9999Collection, `{}`, `[`} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cmw, err := jwt.ParseCMW(data)
		if err != nil {
			return
		}

		if _, err := json.Marshal(cmw); err != nil {
			t.Fatalf("parsed CMW does not marshal: %v", err)
		}
	})
}
