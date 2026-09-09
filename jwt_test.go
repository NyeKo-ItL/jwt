package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

type appClaims struct {
	RegisteredClaims
	Scope string `json:"scope,omitempty"`
}

func ctx() context.Context { return context.Background() }

func TestSignParseRoundTripAllFamilies(t *testing.T) {
	tk := newTestKeys(t)

	hmacS, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	psS, _ := NewRSAPSSSigner(PS256, tk.rsa2048, "r1")
	esS, _ := NewECDSASigner(ES384, tk.p384, "e1")
	edS, _ := NewEd25519Signer(tk.edPriv, "o1")
	rsS := rs256TestSigner{key: tk.rsa2048, kid: "r1"} // caller-supplied, no built-in

	cases := []struct {
		name string
		alg  Algorithm
		sign Signer
		key  Key
	}{
		{"HS256", HS256, hmacS, FromHMACSecret(tk.hmac, "h1")},
		{"PS256", PS256, psS, FromRSAPublicKey(&tk.rsa2048.PublicKey, "r1")},
		{"ES384", ES384, esS, FromECDSAPublicKey(&tk.p384.PublicKey, "e1")},
		{"EdDSA", EdDSA, edS, FromEd25519PublicKey(tk.edPub, "o1")},
		{"RS256-custom-signer", RS256, rsS, FromRSAPublicKey(&tk.rsa2048.PublicKey, "r1")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := appClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:    "https://issuer.example",
					Subject:   "user-1",
					Audience:  Audience{"api"},
					ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  NewNumericDate(time.Now().Add(-time.Minute)),
				},
				Scope: "read",
			}
			tok, err := Sign(in, c.sign)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			out, err := parse[appClaims](ctx(), tok, StaticKeyProvider(c.key),
				WithAllowedAlgorithms(c.alg),
				WithIssuer("https://issuer.example"),
				WithAudience("api"),
			)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if out.Subject != "user-1" || out.Scope != "read" {
				t.Fatalf("claims mismatch: %+v", out)
			}
		})
	}
}

func TestSignStampsDefaultType(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	tok, err := Sign(appClaims{}, s)
	if err != nil {
		t.Fatal(err)
	}
	h, _, _, _ := split3(tok)
	raw, err := b64.Decode(h)
	if err != nil {
		t.Fatal(err)
	}
	var hdr Header
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Type != DefaultType {
		t.Fatalf("typ = %q, want %q", hdr.Type, DefaultType)
	}
}

func TestParseRequiresAllowlist(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	tok, _ := Sign(appClaims{}, s)
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))

	if _, err := parse[appClaims](ctx(), tok, prov); !errors.Is(err, ErrNoAllowedAlgorithms) {
		t.Fatalf("no option: err = %v", err)
	}
	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms()); !errors.Is(err, ErrNoAllowedAlgorithms) {
		t.Fatalf("empty option: err = %v", err)
	}
	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms(Algorithm("none"), "")); !errors.Is(err, ErrNoAllowedAlgorithms) {
		t.Fatalf("none-only option: err = %v", err)
	}
}

func TestParseRejectsAlgNotInAllowlist(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	tok, _ := Sign(appClaims{}, s)
	_, err := parse[appClaims](ctx(), tok, StaticKeyProvider(FromHMACSecret(tk.hmac, "h1")),
		WithAllowedAlgorithms(ES256))
	if !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
	}
}

func TestParseRejectsAlgNone(t *testing.T) {
	tk := newTestKeys(t)
	tok := mintToken(t, Header{Algorithm: "none"}, map[string]string{"sub": "x"}, nil)
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))

	// even if the caller foolishly allowlists "none", it must be rejected
	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms(HS256, Algorithm("none"))); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
	}
	// empty alg is likewise never accepted
	tok2 := mintToken(t, Header{}, map[string]string{"sub": "x"}, nil)
	if _, err := parse[appClaims](ctx(), tok2, prov, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("empty alg err = %v", err)
	}
}

func TestSignRejectsNoneAndNilSigner(t *testing.T) {
	if _, err := Sign(appClaims{}, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("nil signer err = %v", err)
	}
	if _, err := Sign(appClaims{}, staticStr{alg: "none"}); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("none signer err = %v", err)
	}
	if _, err := Sign(appClaims{}, staticStr{alg: ""}); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("empty-alg signer err = %v", err)
	}
}

func TestParseAlgConfusionRSAasHMAC(t *testing.T) {
	tk := newTestKeys(t)
	// Attacker forges an RS256 token, then presents the RSA public key bytes
	// as an HMAC secret. Structural family check must refuse it.
	rsS := rs256TestSigner{key: tk.rsa2048, kid: "r1"}
	tok, err := Sign(appClaims{RegisteredClaims: RegisteredClaims{Subject: "attacker"}}, rsS)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&tk.rsa2048.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	forgedProvider := StaticKeyProvider(FromHMACSecret(pubDER, "r1"))
	if _, err := parse[appClaims](ctx(), tok, forgedProvider, WithAllowedAlgorithms(RS256, HS256)); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("alg-confusion err = %v, want ErrAlgorithmNotAllowed", err)
	}
}

func TestParseSignatureFailure(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	tok, _ := Sign(appClaims{}, s)

	wrong := make([]byte, 64)
	wrong[0] = 0xAB
	_, err := parse[appClaims](ctx(), tok, StaticKeyProvider(FromHMACSecret(wrong, "h1")), WithAllowedAlgorithms(HS256))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong-key verify err = %v, want ErrInvalidSignature", err)
	}
}

func TestParseInvalidPayloadBase64(t *testing.T) {
	tk := newTestKeys(t)
	hdr := b64.Encode([]byte(`{"alg":"HS256","kid":"h1"}`))
	signingInput := hdr + "." + "@@@not-base64@@@"
	m := hmac.New(sha256.New, tk.hmac)
	m.Write([]byte(signingInput))
	tok := signingInput + "." + b64.Encode(m.Sum(nil))

	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("err = %v, want ErrMalformedToken", err)
	}
}

func TestParseTimeChecks(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	now := time.Unix(1_700_000_000, 0)

	expired, _ := Sign(appClaims{RegisteredClaims: RegisteredClaims{ExpiresAt: NewNumericDate(now.Add(-time.Minute))}}, s)
	if _, err := parse[appClaims](ctx(), expired, prov, WithAllowedAlgorithms(HS256), WithClock(func() time.Time { return now })); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired err = %v", err)
	}
	// leeway rescues it
	if _, err := parse[appClaims](ctx(), expired, prov, WithAllowedAlgorithms(HS256),
		WithClock(func() time.Time { return now }), WithLeeway(2*time.Minute)); err != nil {
		t.Fatalf("expired-with-leeway err = %v", err)
	}

	future, _ := Sign(appClaims{RegisteredClaims: RegisteredClaims{NotBefore: NewNumericDate(now.Add(time.Minute))}}, s)
	if _, err := parse[appClaims](ctx(), future, prov, WithAllowedAlgorithms(HS256), WithClock(func() time.Time { return now })); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("nbf err = %v", err)
	}
	if _, err := parse[appClaims](ctx(), future, prov, WithAllowedAlgorithms(HS256),
		WithClock(func() time.Time { return now }), WithLeeway(2*time.Minute)); err != nil {
		t.Fatalf("nbf-with-leeway err = %v", err)
	}
}

func TestParseIssuerAndAudience(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	tok, _ := Sign(appClaims{RegisteredClaims: RegisteredClaims{
		Issuer:   "iss-a",
		Audience: Audience{"aud-1", "aud-2"},
	}}, s)

	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms(HS256), WithIssuer("iss-b")); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("issuer err = %v", err)
	}
	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms(HS256), WithAudience("aud-x")); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("audience err = %v", err)
	}
	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms(HS256), WithIssuer("iss-a"), WithAudience("aud-2")); err != nil {
		t.Fatalf("valid iss/aud err = %v", err)
	}
}

func TestParseRequiredTypeAndClaims(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))

	// Sign() stamps typ: "JWT" (DefaultType), so requiring "JWT" passes.
	plain, _ := Sign(appClaims{Scope: "read"}, s)
	if _, err := parse[appClaims](ctx(), plain, prov, WithAllowedAlgorithms(HS256), WithRequiredType("JWT")); err != nil {
		t.Fatalf("default typ match err = %v", err)
	}
	// ...but requiring a different profile type fails.
	if _, err := parse[appClaims](ctx(), plain, prov, WithAllowedAlgorithms(HS256), WithRequiredType("at+jwt")); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("typ mismatch err = %v", err)
	}
	// A token carrying no typ at all also fails a required-type check.
	untyped := mintToken(t, Header{Algorithm: HS256, KeyID: "h1"}, map[string]any{"scope": "read"}, s)
	if _, err := parse[appClaims](ctx(), untyped, prov, WithAllowedAlgorithms(HS256), WithRequiredType("JWT")); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("missing typ err = %v", err)
	}

	typed := mintToken(t, Header{Algorithm: HS256, Type: "application/at+jwt", KeyID: "h1"},
		map[string]any{"scope": "read"}, s)
	if _, err := parse[appClaims](ctx(), typed, prov, WithAllowedAlgorithms(HS256), WithRequiredType("at+jwt")); err != nil {
		t.Fatalf("typ prefix/case match err = %v", err)
	}

	if _, err := parse[appClaims](ctx(), plain, prov, WithAllowedAlgorithms(HS256), WithRequiredClaims("scope")); err != nil {
		t.Fatalf("present required claim err = %v", err)
	}
	if _, err := parse[appClaims](ctx(), plain, prov, WithAllowedAlgorithms(HS256), WithRequiredClaims("scope", "sub")); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("missing required claim err = %v", err)
	}
}

func TestParseMalformedTokens(t *testing.T) {
	tk := newTestKeys(t)
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	opt := WithAllowedAlgorithms(HS256)

	cases := map[string]string{
		"empty":           "",
		"one segment":     "abc",
		"two segments":    "aaa.bbb",
		"four segments":   "aa.bb.cc.dd",
		"bad b64 header":  "!!!." + b64.Encode([]byte(`{}`)) + ".AA",
		"bad json header": b64.Encode([]byte("not json")) + "." + b64.Encode([]byte(`{}`)) + ".AA",
		"bad b64 sig":     b64.Encode([]byte(`{"alg":"HS256"}`)) + "." + b64.Encode([]byte(`{}`)) + ".!!!",
		"oversized":       strings.Repeat("a", maxTokenBytes+1),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parse[appClaims](ctx(), tok, prov, opt); !errors.Is(err, ErrMalformedToken) && !errors.Is(err, ErrAlgorithmNotAllowed) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestParseBadPayloadJSONAfterValidSig(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	tok := mintToken(t, Header{Algorithm: HS256, KeyID: "h1"}, "not-an-object", s)
	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("err = %v, want ErrMalformedToken", err)
	}
}

func TestParseKeyResolution(t *testing.T) {
	tk := newTestKeys(t)
	s1, _ := NewHMACSigner(HS256, tk.hmac, "k2")
	tok, _ := Sign(appClaims{}, s1)

	other := make([]byte, 64)
	prov := MapKeyProvider(map[string]Key{
		"k1": FromHMACSecret(other, "k1"),
		"k2": FromHMACSecret(tk.hmac, "k2"),
	})
	if _, err := parse[appClaims](ctx(), tok, prov, WithAllowedAlgorithms(HS256)); err != nil {
		t.Fatalf("kid routing err = %v", err)
	}

	// token with an unknown kid
	sX, _ := NewHMACSigner(HS256, tk.hmac, "nope")
	tokX, _ := Sign(appClaims{}, sX)
	if _, err := parse[appClaims](ctx(), tokX, prov, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown kid err = %v", err)
	}

	if _, err := parse[appClaims](ctx(), tok, nil, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("nil provider err = %v", err)
	}
}

type errProvider struct{ err error }

func (e errProvider) Lookup(context.Context, string) (Key, bool, error) { return Key{}, false, e.err }

func TestParsePropagatesProviderError(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	tok, _ := Sign(appClaims{}, s)
	sentinel := errors.New("boom")
	if _, err := parse[appClaims](ctx(), tok, errProvider{err: sentinel}, WithAllowedAlgorithms(HS256)); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
}

func TestParseInsecure(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	expired, _ := Sign(appClaims{
		RegisteredClaims: RegisteredClaims{Subject: "peek", ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour))},
		Scope:            "read",
	}, s)

	out, err := parseInsecure[appClaims](expired)
	if err != nil {
		t.Fatalf("ParseInsecure on expired token: %v", err)
	}
	if out.Subject != "peek" || out.Scope != "read" {
		t.Fatalf("claims mismatch: %+v", out)
	}

	// tampered signature is irrelevant to ParseInsecure
	tampered := expired[:len(expired)-2] + "ZZ"
	if _, err := parseInsecure[appClaims](tampered); err != nil {
		t.Fatalf("ParseInsecure on tampered token: %v", err)
	}

	// a bare header.payload (2 segments) is acceptable
	twoSeg := b64.Encode([]byte(`{"alg":"none"}`)) + "." + b64.Encode([]byte(`{"sub":"x"}`))
	if _, err := parseInsecure[appClaims](twoSeg); err != nil {
		t.Fatalf("ParseInsecure 2-segment: %v", err)
	}

	for _, bad := range []string{"", "onlyonesegment", b64.Encode([]byte(`{}`)) + ".!!!", strings.Repeat("a", maxTokenBytes+1)} {
		if _, err := parseInsecure[appClaims](bad); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("ParseInsecure(%.10q) err = %v", bad, err)
		}
	}
}

func TestSplit3(t *testing.T) {
	cases := []struct {
		in      string
		a, b, c string
		ok      bool
	}{
		{"x.y.z", "x", "y", "z", true},
		{"..", "", "", "", true},
		{"a.b", "", "", "", false},
		{"a.b.c.d", "", "", "", false},
		{"abc", "", "", "", false},
	}
	for _, c := range cases {
		a, b, cc, ok := split3(c.in)
		if ok != c.ok || a != c.a || b != c.b || cc != c.c {
			t.Fatalf("split3(%q) = %q,%q,%q,%v", c.in, a, b, cc, ok)
		}
	}
}

func TestTypeMatches(t *testing.T) {
	cases := []struct {
		got, want string
		ok        bool
	}{
		{"JWT", "jwt", true},
		{"application/at+jwt", "at+jwt", true},
		{"at+jwt", "application/AT+JWT", true},
		{"jwt", "at+jwt", false},
		{"", "jwt", false},
	}
	for _, c := range cases {
		if got := typeMatches(c.got, c.want); got != c.ok {
			t.Fatalf("typeMatches(%q,%q) = %v", c.got, c.want, got)
		}
	}
}

func TestWithoutNone(t *testing.T) {
	got := withoutNone([]Algorithm{HS256, "none", "", "NONE", ES256})
	if len(got) != 2 || got[0] != HS256 || got[1] != ES256 {
		t.Fatalf("withoutNone = %v", got)
	}
}

func TestSignOptions(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))

	decodeHeader := func(tok string) map[string]any {
		h, _, _, _ := split3(tok)
		raw, err := b64.Decode(h)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// WithType overrides "typ"; RFC 9068 round trip.
	at, err := Sign(appClaims{}, s, WithType(AccessTokenType))
	if err != nil {
		t.Fatal(err)
	}
	if decodeHeader(at)["typ"] != AccessTokenType {
		t.Fatalf("typ = %v", decodeHeader(at)["typ"])
	}
	if _, err := parse[appClaims](ctx(), at, prov, WithAllowedAlgorithms(HS256), WithRequiredType(AccessTokenType)); err != nil {
		t.Fatalf("RFC 9068 typ round trip: %v", err)
	}

	// WithType("") omits it.
	none, _ := Sign(appClaims{}, s, WithType(""))
	if _, present := decodeHeader(none)["typ"]; present {
		t.Fatal("WithType(\"\") should omit typ")
	}

	// WithContentType sets "cty"; "alg" stays the signer's.
	full, err := Sign(appClaims{}, s, WithContentType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	hdr := decodeHeader(full)
	if hdr["cty"] != "JWT" || hdr["alg"] != "HS256" {
		t.Fatalf("header = %v", hdr)
	}
}

func TestParseOptionsStruct(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	now := time.Unix(1_700_000_000, 0)

	tok, _ := Sign(appClaims{RegisteredClaims: RegisteredClaims{
		Issuer:    "iss-a",
		Audience:  Audience{"aud-1"},
		ExpiresAt: NewNumericDate(now.Add(-30 * time.Second)), // just expired
	}}, s)

	// A reusable declarative config.
	base := ParseOptions{
		AllowedAlgorithms: []Algorithm{HS256},
		Issuer:            "iss-a",
		Clock:             func() time.Time { return now },
	}

	// struct alone: fails on expiry
	var c1 appClaims
	if err := Parse(ctx(), tok, &c1, prov, base); !errors.Is(err, ErrExpired) {
		t.Fatalf("struct-only err = %v", err)
	}

	// struct + functional overrides combine; later option wins
	var c2 appClaims
	err := Parse(ctx(), tok, &c2, prov, base, WithLeeway(time.Minute), WithAudience("aud-1"))
	if err != nil {
		t.Fatalf("combined err = %v", err)
	}
	if c2.Issuer != "iss-a" {
		t.Fatalf("issuer = %q", c2.Issuer)
	}

	// wrong audience via functional option still rejected on the reused base
	var c3 appClaims
	if err := Parse(ctx(), tok, &c3, prov, base, WithLeeway(time.Minute), WithAudience("nope")); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("audience err = %v", err)
	}

	// a functional option BEFORE the struct is not silently overridden by a
	// zero struct field (empty Issuer in base does not clear it)
	var c4 appClaims
	if err := Parse(ctx(), tok, &c4, prov, WithAudience("aud-1"), WithLeeway(time.Minute),
		ParseOptions{AllowedAlgorithms: []Algorithm{HS256}, Clock: func() time.Time { return now }}); err != nil {
		t.Fatalf("func-then-struct err = %v", err)
	}
}

func TestParseOptionsAcceptedByDecryptAndMiddleware(t *testing.T) {
	tk := newTestKeys(t)
	// DecryptClaims
	enc, _ := NewA256KWEncrypter(tk.hmac[:32], A256GCM, "k")
	dec, _ := NewA256KWDecrypter(tk.hmac[:32], "k")
	compact, _ := EncryptClaims(appClaims{RegisteredClaims: RegisteredClaims{Issuer: "e"}}, enc)
	var got appClaims
	if err := DecryptClaims(ctx(), compact, &got, dec, ParseOptions{Issuer: "e"}); err != nil {
		t.Fatalf("DecryptClaims with ParseOptions: %v", err)
	}
	// Middleware
	_ = Middleware(StaticKeyProvider(FromHMACSecret(tk.hmac, "k")),
		ParseOptions{AllowedAlgorithms: []Algorithm{HS256}})
}

func TestParseOptionsAllFieldsViaStruct(t *testing.T) {
	tk := newTestKeys(t)
	s, _ := NewHMACSigner(HS256, tk.hmac, "h1")
	prov := StaticKeyProvider(FromHMACSecret(tk.hmac, "h1"))
	now := time.Unix(1_700_000_000, 0)

	typed := mintToken(t, Header{Algorithm: HS256, Type: "at+jwt", KeyID: "h1"}, map[string]any{
		"iss":   "iss-x",
		"aud":   "aud-x",
		"scope": "read",
		"exp":   now.Add(-10 * time.Second).Unix(),
	}, s)

	var c appClaims
	err := Parse(ctx(), typed, &c, prov, ParseOptions{
		AllowedAlgorithms: []Algorithm{HS256},
		Issuer:            "iss-x",
		Audience:          "aud-x",
		RequiredType:      "at+jwt",
		RequiredClaims:    []string{"scope"},
		Leeway:            time.Minute,
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("all-struct-fields err = %v", err)
	}
	if c.Scope != "read" {
		t.Fatalf("scope = %q", c.Scope)
	}

	// each constraint really bites
	bad := ParseOptions{AllowedAlgorithms: []Algorithm{HS256}, Clock: func() time.Time { return now }}
	bad.RequiredType = "JWT"
	if err := Parse(ctx(), typed, &c, prov, bad, WithLeeway(time.Minute)); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("RequiredType via struct: %v", err)
	}
	bad2 := ParseOptions{AllowedAlgorithms: []Algorithm{HS256}, Clock: func() time.Time { return now }}
	bad2.RequiredClaims = []string{"missing"}
	if err := Parse(ctx(), typed, &c, prov, bad2, WithLeeway(time.Minute)); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("RequiredClaims via struct: %v", err)
	}
}
