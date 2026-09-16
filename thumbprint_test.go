package jwt

import (
	"crypto"
	"crypto/sha512"
	"errors"
	"strings"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// rfc7638Example is the RSA JWK from RFC 7638 §3.1.
const rfc7638Example = `{"kty":"RSA",` +
	`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4` +
	`cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4` +
	`Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7` +
	`d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3X` +
	`PksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
	`"e":"AQAB","alg":"RS256","kid":"2011-04-29"}`

const rfc7638ExpectedThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

func TestThumbprintRFC7638Vector(t *testing.T) {
	k, err := ParseKey([]byte(rfc7638Example))
	if err != nil {
		t.Fatal(err)
	}

	got, err := Thumbprint(k, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if got != rfc7638ExpectedThumbprint {
		t.Fatalf("thumbprint = %q, want %q", got, rfc7638ExpectedThumbprint)
	}
	// zero hash defaults to SHA-256
	if def, _ := Thumbprint(k, 0); def != rfc7638ExpectedThumbprint {
		t.Fatalf("default-hash thumbprint = %q", def)
	}
}

func TestThumbprintPerKeyType(t *testing.T) {
	tk := newTestKeys(t)
	for _, k := range []Key{
		FromRSAPublicKey(&tk.rsa2048.PublicKey, "r"),
		FromECDSAPublicKey(&tk.p256.PublicKey, "e"),
		FromEd25519PublicKey(tk.edPub, "o"),
		FromHMACSecret(tk.hmac, "h"),
	} {
		got, err := Thumbprint(k, crypto.SHA256)
		if err != nil {
			t.Fatalf("%s: %v", k.Kty, err)
		}

		if len(got) != 43 { // 32 bytes base64url, no padding
			t.Fatalf("%s: thumbprint %q has unexpected length %d", k.Kty, got, len(got))
		}
	}
}

func TestThumbprintRejectsIncompleteKeys(t *testing.T) {
	for _, k := range []Key{
		{Kty: KeyTypeRSA},
		{Kty: KeyTypeEC, crv: "P-256"},
		{Kty: KeyTypeOKP},
		{Kty: KeyTypeOct},
		{Kty: "unknown"},
	} {
		if _, err := Thumbprint(k, crypto.SHA256); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("%+v: err = %v", k, err)
		}
	}
}

func TestThumbprintUnavailableHash(t *testing.T) {
	tk := newTestKeys(t)

	k := FromEd25519PublicKey(tk.edPub, "")
	if _, err := Thumbprint(k, crypto.MD4); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestThumbprintBytes(t *testing.T) {
	tk := newTestKeys(t)

	octDirect, err := ThumbprintBytes(KeyTypeOct, tk.hmac, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	octViaKey, _ := Thumbprint(FromHMACSecret(tk.hmac, ""), crypto.SHA256)
	if octDirect != octViaKey {
		t.Fatalf("oct: %q != %q", octDirect, octViaKey)
	}

	okpDirect, err := ThumbprintBytes(KeyTypeOKP, tk.edPub, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	okpViaKey, _ := Thumbprint(FromEd25519PublicKey(tk.edPub, ""), crypto.SHA256)
	if okpDirect != okpViaKey {
		t.Fatalf("OKP: %q != %q", okpDirect, okpViaKey)
	}

	if _, err := ThumbprintBytes(KeyTypeRSA, tk.hmac, crypto.SHA256); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("RSA via bytes err = %v", err)
	}

	if _, err := ThumbprintBytes(KeyTypeOct, nil, crypto.SHA256); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("empty raw err = %v", err)
	}
}

func TestParseKey(t *testing.T) {
	if _, err := ParseKey([]byte(`{`)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("invalid JSON err = %v", err)
	}

	if _, err := ParseKey([]byte(`{"kid":"x"}`)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("missing kty err = %v", err)
	}

	k, err := ParseKey([]byte(rfc7638Example))
	if err != nil {
		t.Fatal(err)
	}

	if k.Kty != KeyTypeRSA || k.Kid != "2011-04-29" || k.Alg != "RS256" {
		t.Fatalf("parsed key = %+v", k)
	}
}

func TestThumbprintOtherHash(t *testing.T) {
	// RFC 7638 §3.4: any hash may be used; the input is the same canonical
	// JSON (§3.1 shows it for this key), only the digest changes.
	k, err := ParseKey([]byte(rfc7638Example))
	if err != nil {
		t.Fatal(err)
	}

	canonical, err := k.thumbprintInput()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(canonical, `{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4`) {
		t.Fatalf("canonical form = %.60s...", canonical)
	}

	want := sha512.Sum512([]byte(canonical))

	got, err := Thumbprint(k, crypto.SHA512)
	if err != nil || got != b64.Encode(want[:]) {
		t.Fatalf("SHA-512 thumbprint = %q (%v)", got, err)
	}
}
