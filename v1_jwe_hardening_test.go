package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

var v1JWEAllow = ParseOptions{
	AllowedKeyAlgorithms:     []KeyAlgorithm{Direct, A256KW, ECDHES, ECDHESA256KW, RSAOAEP256},
	AllowedContentAlgorithms: []ContentAlgorithm{A128GCM, A192GCM, A256GCM},
}

func TestV1JWEDecryptClaimsAtomicAndNilOptions(t *testing.T) {
	cek := mkKEK(32)

	enc, err := NewDirectEncrypter(cek, A256GCM)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := NewDirectDecrypter(cek)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := EncryptClaims(map[string]any{"sub": "new"}, enc)
	if err != nil {
		t.Fatal(err)
	}

	dst := appClaims{RegisteredClaims: RegisteredClaims{Subject: "old"}, Scope: "stale"}

	var (
		nilOption  ParseOption
		nilOptions *ParseOptions
	)
	if err := DecryptClaims(context.Background(), tok, &dst, dec, v1JWEAllow, nilOption, nilOptions); err != nil {
		t.Fatalf("DecryptClaims: %v", err)
	}

	if dst.Subject != "new" || dst.Scope != "" {
		t.Fatalf("destination was not replaced from a fresh value: %+v", dst)
	}

	bad := sealJWE(t, `{"alg":"dir","enc":"A256GCM"}`, nil, cek, []byte(`{"sub":"changed","scope":1}`))

	dst = appClaims{RegisteredClaims: RegisteredClaims{Subject: "keep"}, Scope: "keep"}
	if err := DecryptClaims(context.Background(), bad, &dst, dec, v1JWEAllow); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("bad destination decode: %v", err)
	}

	if dst.Subject != "keep" || dst.Scope != "keep" {
		t.Fatalf("failed decode mutated destination: %+v", dst)
	}

	if err := DecryptClaims[appClaims](context.Background(), tok, nil, dec, v1JWEAllow); !errors.Is(err, ErrInvalidDestination) {
		t.Fatalf("nil destination: %v", err)
	}
}

func TestV1JWEEncryptClaimsRequiresJSONObjectAndSupportsOptions(t *testing.T) {
	cek := mkKEK(32)

	enc, err := NewDirectEncrypter(cek, A256GCM)
	if err != nil {
		t.Fatal(err)
	}

	for name, claims := range map[string]any{
		"array":  []int{1, 2},
		"string": "claims",
		"number": 1,
		"null":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := EncryptClaims(claims, enc); !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("err = %v, want ErrInvalidClaims", err)
			}
		})
	}

	reusable := EncryptOptions{Type: "example+jwt", ContentType: "json"}

	var (
		nilOption  EncryptOption
		nilOptions *EncryptOptions
	)

	tok, err := EncryptClaims(map[string]string{"sub": "u"}, enc, reusable, nilOption, nilOptions)
	if err != nil {
		t.Fatal(err)
	}

	_, hdr, err := parseJWEProtected(tok)
	if err != nil {
		t.Fatal(err)
	}

	if hdr.Typ != "example+jwt" || hdr.Cty != "json" {
		t.Fatalf("protected header = typ %q, cty %q", hdr.Typ, hdr.Cty)
	}
}

type v1CustomEncrypter struct{}

func (v1CustomEncrypter) KeyAlgorithm() KeyAlgorithm         { return Direct }
func (v1CustomEncrypter) ContentAlgorithm() ContentAlgorithm { return A256GCM }
func (v1CustomEncrypter) KeyID() string                      { return "" }
func (v1CustomEncrypter) Encrypt([]byte) (string, error)     { return "custom", nil }

func TestV1JWEOptionsRefuseUnsupportedCustomEncrypter(t *testing.T) {
	var nilEncrypter *encrypter
	if _, err := EncryptJWE(nil, nilEncrypter); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("typed nil encrypter: %v", err)
	}

	if got, err := EncryptJWE(nil, v1CustomEncrypter{}, nil); err != nil || got != "custom" {
		t.Fatalf("no effective options: got %q, err %v", got, err)
	}

	if _, err := EncryptJWE(nil, v1CustomEncrypter{}, WithJWEType("JWT")); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("configured custom encrypter: %v", err)
	}
}

func TestV1JWEAESKWKnownVectorAndExactLengthGuards(t *testing.T) {
	kek := mustB64(t, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	plaintext := mustB64(t, "ABEiM0RVZneImaq7zN3u_w")
	want := "ZOjD-c4PW6Jj6Xd5BYGKKpPIGR59born"

	wrapped, err := aesKWWrap(kek, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if got := b64.Encode(wrapped); got != want {
		t.Fatalf("wrapped = %s, want %s", got, want)
	}

	unwrapped, err := aesKWUnwrap(kek, wrapped)
	if err != nil || string(unwrapped) != string(plaintext) {
		t.Fatalf("unwrap = %x, %v", unwrapped, err)
	}

	u := aesKWUnwrapper{kek: kek}
	for _, n := range []int{0, 24, 39, 41, 1 << 20} {
		if _, err := u.unwrap(nil, make([]byte, n), 32); !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("length %d: %v", n, err)
		}
	}
}

func BenchmarkV1JWEAESKWRejectHostileEncryptedKey(b *testing.B) {
	u := aesKWUnwrapper{kek: make([]byte, 32)}
	hostile := make([]byte, 1<<20)

	b.ReportAllocs()
	b.SetBytes(int64(len(hostile)))

	for range b.N {
		_, _ = u.unwrap(nil, hostile, 32)
	}
}

func TestV1JWEECDHRejectsEqualPartyInfoIncludingExplicitEmpty(t *testing.T) {
	tk := newTestKeys(t)

	dec, err := NewECDHESDecrypter(tk.p256)
	if err != nil {
		t.Fatal(err)
	}

	epk, err := FromECDSAPublicKey(&tk.p256.PublicKey).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	z, err := ecdhZ(tk.p256, &tk.p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	for name, fields := range map[string]string{
		"explicit empty": `"apu":"","apv":"",`,
		"same value":     `"apu":"c2FtZQ","apv":"c2FtZQ",`,
	} {
		t.Run(name, func(t *testing.T) {
			party := []byte(nil)
			if strings.Contains(fields, "c2FtZQ") {
				party = []byte("same")
			}

			cek := concatKDF(z, string(A256GCM), party, party, 256)
			hdr := `{"alg":"ECDH-ES","enc":"A256GCM",` + fields + `"epk":` + string(epk) + `}`

			tok := sealJWE(t, hdr, nil, cek, []byte(`{}`))
			if _, err := dec.Decrypt(context.Background(), tok); !errors.Is(err, ErrDecryptionFailed) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	cek := concatKDF(z, string(A256GCM), nil, []byte("recipient"), 256)

	hdr := `{"alg":"ECDH-ES","enc":"A256GCM","apu":"","apv":"cmVjaXBpZW50","epk":` + string(epk) + `}`
	if _, err := dec.Decrypt(context.Background(), sealJWE(t, hdr, nil, cek, []byte(`{}`))); err != nil {
		t.Fatalf("distinct party info rejected: %v", err)
	}
}

func TestV1JWEEPKRejectsEveryPrivateParameter(t *testing.T) {
	tk := newTestKeys(t)

	epk, err := FromECDSAPublicKey(&tk.p256.PublicKey).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	base := strings.TrimSuffix(string(epk), "}")

	for _, name := range []string{"d", "k", "p", "q", "dp", "dq", "qi", "oth"} {
		t.Run(name, func(t *testing.T) {
			raw := `{"alg":"ECDH-ES","enc":"A256GCM","epk":` + base + `,"` + name + `":""}}`

			compact := b64.Encode([]byte(raw)) + "...."
			if _, _, err := parseJWEProtected(compact); !errors.Is(err, ErrDecryptionFailed) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestV1JWENestedSignedThenEncrypted(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	signer, err := NewHMACSigner(HS256, secret, "sig-1")
	if err != nil {
		t.Fatal(err)
	}

	inner, err := Sign(appClaims{RegisteredClaims: RegisteredClaims{Issuer: "issuer", Subject: "alice"}, Scope: "read"}, signer)
	if err != nil {
		t.Fatal(err)
	}

	cek := mkKEK(32)
	enc, _ := NewDirectEncrypter(cek, A256GCM, "enc-1")
	dec, _ := NewDirectDecrypter(cek, "enc-1")

	outer, err := EncryptNestedJWT(inner, enc, WithJWEType("nested+jwt"), WithJWEContentType("ignored"))
	if err != nil {
		t.Fatal(err)
	}

	_, hdr, err := parseJWEProtected(outer)
	if err != nil || hdr.Cty != "JWT" {
		t.Fatalf("outer cty = %q, err %v", hdr.Cty, err)
	}

	policies := NestedJWTPolicies{
		JWE: []ParseOption{WithAllowedKeyAlgorithms(Direct), WithAllowedContentAlgorithms(A256GCM), WithRequiredType("nested+jwt")},
		JWS: []ParseOption{WithAllowedAlgorithms(HS256), WithIssuer("issuer")},
	}
	keys := StaticKeyProvider(FromHMACSecret(secret, "sig-1"))

	var got appClaims
	if err := DecryptNestedJWT(context.Background(), outer, &got, dec, keys, policies); err != nil {
		t.Fatal(err)
	}

	if got.Subject != "alice" || got.Scope != "read" {
		t.Fatalf("claims = %+v", got)
	}

	parts := strings.Split(inner, ".")
	sig, _ := b64.Decode(parts[2])
	sig[0] ^= 0xff
	tamperedInner := parts[0] + "." + parts[1] + "." + b64.Encode(sig)

	tamperedOuter, err := EncryptNestedJWT(tamperedInner, enc, WithJWEType("nested+jwt"))
	if err != nil {
		t.Fatal(err)
	}

	got = appClaims{RegisteredClaims: RegisteredClaims{Subject: "keep"}, Scope: "keep"}
	if err := DecryptNestedJWT(context.Background(), tamperedOuter, &got, dec, keys, policies); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered inner signature: %v", err)
	}

	if got.Subject != "keep" || got.Scope != "keep" {
		t.Fatalf("nested failure mutated destination: %+v", got)
	}

	noContentType, err := EncryptJWE([]byte(inner), enc)
	if err != nil {
		t.Fatal(err)
	}

	if err := DecryptNestedJWT(context.Background(), noContentType, &got, dec, keys, policies); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("missing outer cty: %v", err)
	}

	withoutJWSAllowlist := policies

	withoutJWSAllowlist.JWS = nil
	if err := DecryptNestedJWT(context.Background(), outer, &got, dec, keys, withoutJWSAllowlist); !errors.Is(err, ErrNoAllowedAlgorithms) {
		t.Fatalf("distinct inner policy: %v", err)
	}
}

func TestV1JWEDecrypterKeyIDPolicy(t *testing.T) {
	cek := mkKEK(32)
	withKID, _ := NewDirectEncrypter(cek, A256GCM, "enc-a")
	withoutKID, _ := NewDirectEncrypter(cek, A256GCM)
	matching, _ := NewDirectDecrypter(cek, "enc-a")
	other, _ := NewDirectDecrypter(cek, "enc-b")
	unspecified, _ := NewDirectDecrypter(cek)

	withToken, _ := withKID.Encrypt([]byte("x"))
	withoutToken, _ := withoutKID.Encrypt([]byte("x"))

	if _, err := other.Decrypt(context.Background(), withToken); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("mismatched kid: %v", err)
	}

	if _, err := matching.Decrypt(context.Background(), withoutToken); err != nil {
		t.Fatalf("absent header kid: %v", err)
	}

	if _, err := unspecified.Decrypt(context.Background(), withToken); err != nil {
		t.Fatalf("absent decrypter kid: %v", err)
	}
}

func TestV1JWEECDHRejectsPartialKeysAtConstruction(t *testing.T) {
	partialPublic := &ecdsa.PublicKey{Curve: elliptic.P256()}
	if _, err := NewECDHESEncrypter(partialPublic, ECDHES, A256GCM); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("partial public key: %v", err)
	}

	partialPrivate := &ecdsa.PrivateKey{PublicKey: *partialPublic}
	if _, err := NewECDHESDecrypter(partialPrivate); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("partial private key: %v", err)
	}

	var (
		nilDecrypter *decrypter
		dst          appClaims
	)
	if err := DecryptClaims(context.Background(), "", &dst, nilDecrypter, v1JWEAllow); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("typed nil decrypter: %v", err)
	}
}

func TestV1JWERSARejectsPartialInvalidAndOversizedKeys(t *testing.T) {
	tk := newTestKeys(t)

	publicCases := map[string]*rsa.PublicKey{
		"missing modulus":  {E: 65537},
		"missing exponent": {N: new(big.Int).Set(tk.rsa2048.N)},
		"even exponent":    {N: new(big.Int).Set(tk.rsa2048.N), E: 4},
		"even modulus":     {N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537},
		"oversized":        {N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), maxJWERSABits), big.NewInt(1)), E: 65537},
	}
	for name, pub := range publicCases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRSAOAEP256Encrypter(pub, A256GCM); !errors.Is(err, ErrMalformedKey) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	partial := &rsa.PrivateKey{PublicKey: tk.rsa2048.PublicKey}
	if _, err := NewRSAOAEP256Decrypter(partial); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("partial private key: %v", err)
	}

	inconsistent := *tk.rsa2048

	inconsistent.D = new(big.Int).Add(tk.rsa2048.D, big.NewInt(1))
	if _, err := NewRSAOAEP256Decrypter(&inconsistent); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("inconsistent private key: %v", err)
	}
}
