package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// signRawHS256 builds a compact JWS from verbatim header and payload JSON, so
// tests can craft byte-exact edge cases (duplicate names, odd casing, ...)
// that a well-behaved encoder would never produce. The signature is valid:
// every rejection below is therefore a parsing decision, not a crypto one.
func signRawHS256(key []byte, headerJSON, payloadJSON string) string {
	input := b64.Encode([]byte(headerJSON)) + "." + b64.Encode([]byte(payloadJSON))
	m := hmac.New(sha256.New, key)
	m.Write([]byte(input))

	return input + "." + b64.Encode(m.Sum(nil))
}

func strictFixture(t *testing.T) ([]byte, KeyProvider) {
	t.Helper()

	key := newTestKeys(t).hmac

	return key, StaticKeyProvider(FromHMACSecret(key))
}

// ---- RFC 7515 §4.1.11 "crit" -------------------------------------------------

func TestParseRejectsCriticalHeaders(t *testing.T) {
	key, keys := strictFixture(t)

	cases := map[string]string{
		// No extension is understood by this library, so any listed name must
		// cause rejection (§4.1.11: "If any of the listed extension Header
		// Parameters are not understood and supported by the recipient, then
		// the JWS is invalid").
		"unknown extension":      `{"alg":"HS256","crit":["exp-ext"],"exp-ext":1}`,
		"RFC 7797 b64":           `{"alg":"HS256","crit":["b64"],"b64":false}`,
		"listed but absent":      `{"alg":"HS256","crit":["missing"]}`,
		"empty list":             `{"alg":"HS256","crit":[]}`,
		"registered name alg":    `{"alg":"HS256","crit":["alg"]}`,
		"registered name kid":    `{"alg":"HS256","kid":"k","crit":["kid"]}`,
		"registered JWE name":    `{"alg":"HS256","crit":["enc"],"enc":"A128GCM"}`,
		"null":                   `{"alg":"HS256","crit":null}`,
		"not an array":           `{"alg":"HS256","crit":"exp-ext","exp-ext":1}`,
		"array of non-strings":   `{"alg":"HS256","crit":[1]}`,
		"one good one unknown":   `{"alg":"HS256","crit":["a","b"],"a":1,"b":2}`,
		"duplicate crit members": `{"alg":"HS256","crit":["a"],"crit":["a"],"a":1}`,
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			tok := signRawHS256(key, hdr, `{}`)
			if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256)); err == nil {
				t.Fatalf("header %s accepted", hdr)
			}
		})
	}
}

func TestParseCriticalHeaderErrorIsTyped(t *testing.T) {
	key, keys := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256","crit":["exp-ext"],"exp-ext":1}`, `{}`)

	if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrUnsupportedCritical) {
		t.Fatalf("err = %v, want ErrUnsupportedCritical", err)
	}
}

func TestCriticalHeaderCheckedBeforeKeyLookup(t *testing.T) {
	key, _ := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256","crit":["x"],"x":1}`, `{}`)

	lookups := 0
	keys := keyProviderFunc(func(string) (Key, bool, error) {
		lookups++
		return FromHMACSecret(key), true, nil
	})

	_, _ = parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256))

	if lookups != 0 {
		t.Fatal("a token with unsupported crit reached the KeyProvider")
	}
}

func TestParseWithoutCritStillWorks(t *testing.T) {
	key, keys := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256","typ":"JWT"}`, `{"sub":"s"}`)

	got, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256))
	if err != nil || got.Subject != "s" {
		t.Fatalf("plain token: %v %+v", err, got)
	}
}

// ---- exact JSON member names, no duplicates (RFC 7515 §4, RFC 7519 §4) --------

func TestParseHeaderNamesAreCaseSensitive(t *testing.T) {
	key, keys := strictFixture(t)

	for _, hdr := range []string{
		`{"ALG":"HS256"}`,
		`{"Alg":"HS256"}`,
		`{"alg":"HS256","CRIT":["x"],"x":1}`, // must not dodge the crit check either
	} {
		tok := signRawHS256(key, hdr, `{}`)

		_, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256))
		if strings.HasPrefix(hdr, `{"alg"`) {
			// "CRIT" is simply an unknown (ignored) member, not "crit".
			if err != nil {
				t.Fatalf("header %s: %v", hdr, err)
			}

			continue
		}

		if !errors.Is(err, ErrAlgorithmNotAllowed) {
			t.Fatalf("header %s: err = %v, want ErrAlgorithmNotAllowed (no \"alg\" member)", hdr, err)
		}
	}
}

func TestParseClaimNamesAreCaseSensitive(t *testing.T) {
	key, keys := strictFixture(t)
	past := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)

	// A mis-cased "EXP" is not the registered "exp" claim: it must neither
	// expire the token nor populate RegisteredClaims.
	tok := signRawHS256(key, `{"alg":"HS256"}`, `{"ISS":"me","EXP":`+past+`,"Scope":"admin"}`)

	got, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.Issuer != "" || got.ExpiresAt != nil || got.Scope != "" {
		t.Fatalf("mis-cased members populated fields: %+v", got)
	}

	if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256), WithIssuer("me")); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("\"ISS\" satisfied WithIssuer: %v", err)
	}
}

func TestParseRejectsDuplicateMemberNames(t *testing.T) {
	key, keys := strictFixture(t)

	cases := map[string][2]string{
		"duplicate header alg":     {`{"alg":"none","alg":"HS256"}`, `{}`},
		"duplicate registered exp": {`{"alg":"HS256"}`, `{"exp":1,"exp":99999999999}`},
		"duplicate custom claim":   {`{"alg":"HS256"}`, `{"scope":"user","scope":"admin"}`},
		"duplicate nested member":  {`{"alg":"HS256"}`, `{"cnf":{"jkt":"a","jkt":"b"}}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tok := signRawHS256(key, c[0], c[1])
			if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("err = %v, want ErrMalformedToken", err)
			}
		})
	}
}

func TestParseRejectsInvalidUTF8(t *testing.T) {
	key, keys := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256"}`, "{\"sub\":\"\xff\"}")

	if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("invalid UTF-8 claim: %v", err)
	}
}

func TestParseRejectsNonObjectPayload(t *testing.T) {
	key, keys := strictFixture(t)

	for _, payload := range []string{`[]`, `"s"`, `1`, `null`, ``} {
		tok := signRawHS256(key, `{"alg":"HS256"}`, payload)
		if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("payload %q: %v", payload, err)
		}
	}
}

func TestParseInsecureUsesSameStrictDecoding(t *testing.T) {
	tok := signRawHS256([]byte("k"), `{"alg":"HS256"}`, `{"sub":"a","sub":"b"}`)
	if _, err := parseInsecure[appClaims](tok); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("duplicate claim via ParseInsecure: %v", err)
	}

	tok = signRawHS256([]byte("k"), `{"alg":"HS256"}`, `{"SUB":"a"}`)
	if got, err := parseInsecure[appClaims](tok); err != nil || got.Subject != "" {
		t.Fatalf("mis-cased claim via ParseInsecure: %v %+v", err, got)
	}
}

func TestParseStrictDecodingKeepsProviderStructsWorking(t *testing.T) {
	key, keys := strictFixture(t)
	payload := `{"iss":"https://accounts.google.com","sub":"1","aud":"c","exp":99999999999,` +
		`"email":"a@b.c","email_verified":true,"hd":"b.c","azp":"c"}`
	tok := signRawHS256(key, `{"alg":"HS256"}`, payload)

	got, err := parse[GoogleIDToken](ctx(), tok, keys, WithAllowedAlgorithms(HS256), WithAudience("c"))
	if err != nil || got.Email != "a@b.c" || got.HostedDomain != "b.c" || got.EmailVerified == nil || !*got.EmailVerified {
		t.Fatalf("GoogleIDToken: %v %+v", err, got)
	}

	var m map[string]any
	if err := ParseInsecure(tok, &m); err != nil || m["hd"] != "b.c" {
		t.Fatalf("map destination: %v %v", err, m)
	}
}

// ---- canonical base64url (RFC 7515 §2, RFC 4648 §3.5) --------------------------

func TestParseRejectsNonCanonicalBase64(t *testing.T) {
	key, keys := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256"}`, `{}`)
	h, p, s, _ := split3(tok)

	// A 32-byte HMAC is 43 base64url characters; the last one carries two
	// unused low bits. Setting them yields a different string that a lenient
	// decoder maps to the same bytes.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	last := strings.IndexByte(alphabet, s[len(s)-1])
	sigTwin := s[:len(s)-1] + string(alphabet[last|1])

	variants := map[string]string{
		"signature trailing bits": h + "." + p + "." + sigTwin,
		"LF in signature":         h + "." + p + "." + s[:10] + "\n" + s[10:],
		"CR in signature":         h + "." + p + "." + s[:10] + "\r" + s[10:],
		"padding in signature":    h + "." + p + "." + s + "=",
	}
	for name, tok := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("err = %v, want ErrMalformedToken", err)
			}
		})
	}
}

// ---- RFC 7515 §4.1.9 "typ" media-type comparison --------------------------------

func TestTypeMatchesMediaTypeRules(t *testing.T) {
	cases := []struct {
		got, want string
		ok        bool
	}{
		{"JWT", "JWT", true},
		{"jwt", "JWT", true},                   // media types are case-insensitive (RFC 2045 §5.1)
		{"application/jwt", "JWT", true},       // "application/" is implied when no "/" appears
		{"at+jwt", "application/at+jwt", true}, // ... in either argument
		{"APPLICATION/AT+JWT", "at+jwt", true}, // case-insensitive prefix too
		{"evil/at+jwt", "at+jwt", false},       // only the application/ prefix may be omitted
		{"text/jwt", "JWT", false},             // a different top-level type is a different type
		{"application/evil/at+jwt", "at+jwt", false},
		{"at+jwt", "jwt", false},
		{" JWT", "JWT", false}, // no whitespace trimming
		{"", "JWT", false},
		{"JWT", "", false},
	}
	for _, c := range cases {
		if got := typeMatches(c.got, c.want); got != c.ok {
			t.Errorf("typeMatches(%q, %q) = %v, want %v", c.got, c.want, got, c.ok)
		}
	}
}

func TestParseRequiredTypeRejectsForeignMediaType(t *testing.T) {
	key, keys := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256","typ":"evil/at+jwt"}`, `{}`)

	if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256), WithRequiredType(AccessTokenType)); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("err = %v, want ErrTypeMismatch", err)
	}
}

// ---- RFC 7519 §2 NumericDate -----------------------------------------------------

func TestNumericDateStrict(t *testing.T) {
	ok := []struct {
		in   string
		unix int64
		nsec int
	}{
		{`0`, 0, 0},
		{`1609459200`, 1609459200, 0},
		{`1609459200.0`, 1609459200, 0},
		{`1609459200.25`, 1609459200, 250_000_000},
		{`1.6094592e9`, 1609459200, 0},
		{`-1`, -1, 0},
		{`253402300799`, 253402300799, 0}, // 9999-12-31T23:59:59Z, the upper bound
		{`-62135596800`, -62135596800, 0}, // 0001-01-01T00:00:00Z, the lower bound
	}
	for _, c := range ok {
		var n NumericDate
		if err := n.UnmarshalJSON([]byte(c.in)); err != nil {
			t.Errorf("UnmarshalJSON(%s): %v", c.in, err)
			continue
		}

		if n.Unix() != c.unix || n.Nanosecond() != c.nsec || n.Location() != time.UTC {
			t.Errorf("UnmarshalJSON(%s) = %v", c.in, n.Time)
		}
	}

	bad := []string{
		`"1609459200"`, // a string is not a JSON numeric value
		`"Inf"`, `"NaN"`, `"-Inf"`,
		`1e300`, `-1e300`,
		`253402300800`, // past year 9999
		`-62135596801`, // before year 1
		strconv.FormatFloat(math.MaxFloat64, 'g', -1, 64),
		`true`, `{}`, `[]`, `"abc"`, `1 2`, `01`,
	}
	for _, in := range bad {
		var n NumericDate
		if err := n.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("UnmarshalJSON(%s) accepted, got %v", in, n.Time)
		}
	}
}

func TestParseRejectsNonNumericDates(t *testing.T) {
	key, keys := strictFixture(t)

	for _, claim := range []string{"exp", "nbf", "iat"} {
		for _, v := range []string{`"Inf"`, `"99999999999"`, `1e300`} {
			tok := signRawHS256(key, `{"alg":"HS256"}`, `{"`+claim+`":`+v+`}`)
			if _, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrMalformedToken) {
				t.Errorf("%s=%s: err = %v, want ErrMalformedToken", claim, v, err)
			}
		}
	}
}

func TestParseNullDatesAreAbsent(t *testing.T) {
	key, keys := strictFixture(t)
	tok := signRawHS256(key, `{"alg":"HS256"}`, `{"exp":null,"nbf":null}`)

	got, err := parse[appClaims](ctx(), tok, keys, WithAllowedAlgorithms(HS256))
	if err != nil || got.ExpiresAt != nil || got.NotBefore != nil {
		t.Fatalf("null dates: %v %+v", err, got)
	}
}
