package jwt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// jweAllow is the allowlist matching every built-in algorithm, for tests that
// exercise something other than the allowlist itself.
var jweAllow = ParseOptions{
	AllowedKeyAlgorithms:     []KeyAlgorithm{RSAOAEP256, A256KW, ECDHES, ECDHESA256KW, Direct},
	AllowedContentAlgorithms: []ContentAlgorithm{A128GCM, A192GCM, A256GCM},
}

// sealJWE assembles a compact JWE with a caller-chosen protected header and
// CEK — used to build RFC test vectors and hostile-but-authentic tokens.
func sealJWE(t *testing.T, protectedJSON string, encryptedKey, cek, plaintext []byte) string {
	t.Helper()

	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}

	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())
	protected := b64.Encode([]byte(protectedJSON))
	sealed := gcm.Seal(nil, iv, plaintext, []byte(protected))
	ct, tag := sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():]

	return strings.Join([]string{protected, b64.Encode(encryptedKey), b64.Encode(iv), b64.Encode(ct), b64.Encode(tag)}, ".")
}

// ---- mandatory alg/enc allowlist (spec §4.1, RFC 8725 §3.1) ----------------------

func TestDecryptClaimsRequiresAllowlists(t *testing.T) {
	cek := mkKEK(32)
	enc, _ := NewDirectEncrypter(cek, A256GCM)
	dec, _ := NewDirectDecrypter(cek)
	tok, _ := EncryptClaims(appClaims{}, enc)

	cases := map[string][]ParseOption{
		"none":                        nil,
		"only key algorithms":         {WithAllowedKeyAlgorithms(Direct)},
		"only content algorithms":     {WithAllowedContentAlgorithms(A256GCM)},
		"JWS allowlist is not enough": {WithAllowedAlgorithms(HS256)},
		"only none-like entries":      {WithAllowedKeyAlgorithms("", "none"), WithAllowedContentAlgorithms("NONE")},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decryptClaims[appClaims](ctx(), tok, dec, opts...); !errors.Is(err, ErrNoAllowedAlgorithms) {
				t.Fatalf("err = %v, want ErrNoAllowedAlgorithms", err)
			}
		})
	}
}

func TestDecryptClaimsEnforcesAllowlists(t *testing.T) {
	tk := newTestKeys(t)
	enc, _ := NewECDHESEncrypter(&tk.p256.PublicKey, ECDHESA256KW, A128GCM)
	dec, _ := NewECDHESDecrypter(tk.p256)
	tok, _ := EncryptClaims(appClaims{}, enc)

	cases := []struct {
		name string
		keys []KeyAlgorithm
		encs []ContentAlgorithm
		ok   bool
	}{
		{"exact", []KeyAlgorithm{ECDHESA256KW}, []ContentAlgorithm{A128GCM}, true},
		{"supersets", []KeyAlgorithm{ECDHES, ECDHESA256KW}, []ContentAlgorithm{A128GCM, A256GCM}, true},
		// the ECDH decrypter can do both ECDH-ES modes; the allowlist narrows it
		{"sibling key algorithm only", []KeyAlgorithm{ECDHES}, []ContentAlgorithm{A128GCM}, false},
		{"enc downgrade refused", []KeyAlgorithm{ECDHESA256KW}, []ContentAlgorithm{A256GCM}, false},
		{"case differs", []KeyAlgorithm{"ecdh-es+a256kw"}, []ContentAlgorithm{A128GCM}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decryptClaims[appClaims](ctx(), tok, dec,
				WithAllowedKeyAlgorithms(tc.keys...), WithAllowedContentAlgorithms(tc.encs...))
			if tc.ok && err != nil {
				t.Fatalf("err = %v", err)
			}

			if !tc.ok && !errors.Is(err, ErrAlgorithmNotAllowed) {
				t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
			}
		})
	}
}

// customDecrypter reports success for anything: the allowlist must still apply,
// independently of what a caller-supplied Decrypter accepts (spec §4.2).
type customDecrypter struct{ calls int }

func (*customDecrypter) KeyID() string { return "" }
func (d *customDecrypter) Decrypt(_ context.Context, _ string) ([]byte, error) {
	d.calls++
	return []byte(`{}`), nil
}

func TestDecryptClaimsAllowlistAppliesToCustomDecrypter(t *testing.T) {
	d := &customDecrypter{}
	hdr := b64.Encode([]byte(`{"alg":"RSA1_5","enc":"A128CBC-HS256"}`))
	tok := hdr + ".AA.AA.AA.AA"

	if _, err := decryptClaims[appClaims](ctx(), tok, d, jweAllow); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
	}

	if d.calls != 0 {
		t.Fatal("custom Decrypter reached despite a disallowed algorithm")
	}

	if _, err := decryptClaims[appClaims](ctx(), tok, d,
		WithAllowedKeyAlgorithms("RSA1_5"), WithAllowedContentAlgorithms("A128CBC-HS256")); err != nil || d.calls != 1 {
		t.Fatalf("explicitly allowed custom algorithm: err=%v calls=%d", err, d.calls)
	}
}

func TestParseOptionsCarriesJWEAllowlists(t *testing.T) {
	cek := mkKEK(16)
	enc, _ := NewDirectEncrypter(cek, A128GCM)
	dec, _ := NewDirectDecrypter(cek)
	tok, _ := EncryptClaims(appClaims{}, enc)

	opts := ParseOptions{AllowedKeyAlgorithms: []KeyAlgorithm{Direct}, AllowedContentAlgorithms: []ContentAlgorithm{A128GCM}}
	if _, err := decryptClaims[appClaims](ctx(), tok, dec, opts); err != nil {
		t.Fatalf("struct allowlists: %v", err)
	}
}

// ---- size cap (spec §4.11) --------------------------------------------------------

func TestDecryptRejectsOversizedInput(t *testing.T) {
	cek := mkKEK(32)
	dec, _ := NewDirectDecrypter(cek)
	huge := strings.Repeat("A", maxTokenBytes) + "...AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"

	if _, err := dec.Decrypt(ctx(), huge); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt oversized: %v", err)
	}

	if _, err := decryptClaims[appClaims](ctx(), huge, dec, jweAllow); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("DecryptClaims oversized: %v", err)
	}
}

// ---- "zip" and "crit" (RFC 7516 §4.1.3, §4.1.13) -----------------------------------

func TestDecryptRejectsZipAndCrit(t *testing.T) {
	cek := mkKEK(32)
	dec, _ := NewDirectDecrypter(cek)

	cases := map[string]struct {
		hdr  string
		want error
	}{
		"zip DEF":        {`{"alg":"dir","enc":"A256GCM","zip":"DEF"}`, ErrDecryptionFailed},
		"zip empty":      {`{"alg":"dir","enc":"A256GCM","zip":""}`, ErrDecryptionFailed},
		"crit extension": {`{"alg":"dir","enc":"A256GCM","crit":["x"],"x":1}`, ErrUnsupportedCritical},
		"crit empty":     {`{"alg":"dir","enc":"A256GCM","crit":[]}`, ErrUnsupportedCritical},
		"duplicate alg":  {`{"alg":"dir","alg":"dir","enc":"A256GCM"}`, ErrDecryptionFailed},
		"mis-cased enc":  {`{"alg":"dir","ENC":"A256GCM"}`, ErrDecryptionFailed},
		"not an object":  {`["dir"]`, ErrDecryptionFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Authentic: sealed under the right CEK with this exact header as AAD.
			tok := sealJWE(t, tc.hdr, nil, cek, []byte(`{}`))

			if _, err := dec.Decrypt(ctx(), tok); !errors.Is(err, ErrDecryptionFailed) {
				t.Fatalf("Decrypt: err = %v, want ErrDecryptionFailed", err)
			}

			if _, err := decryptClaims[appClaims](ctx(), tok, dec, jweAllow); !errors.Is(err, tc.want) {
				t.Fatalf("DecryptClaims: err = %v, want %v", err, tc.want)
			}
		})
	}
}

// ---- explicit typing for JWE (RFC 8725 §3.11) ----------------------------------------

func TestDecryptClaimsRequiredType(t *testing.T) {
	cek := mkKEK(32)
	dec, _ := NewDirectDecrypter(cek)

	typed := sealJWE(t, `{"alg":"dir","enc":"A256GCM","typ":"secevent+jwt"}`, nil, cek, []byte(`{}`))
	untyped := sealJWE(t, `{"alg":"dir","enc":"A256GCM"}`, nil, cek, []byte(`{}`))

	if _, err := decryptClaims[appClaims](ctx(), typed, dec, jweAllow, WithRequiredType("application/secevent+jwt")); err != nil {
		t.Fatalf("matching typ: %v", err)
	}

	if _, err := decryptClaims[appClaims](ctx(), untyped, dec, jweAllow, WithRequiredType("secevent+jwt")); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("missing typ: %v", err)
	}
}

// ---- ECDH-ES PartyUInfo / PartyVInfo (RFC 7518 §4.6.1.2–3, Appendix C) ---------------

// RFC 7518 Appendix C key material: Bob's static key and Alice's ephemeral key.
const (
	appCBobX   = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ"
	appCBobY   = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
	appCBobD   = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
	appCAliceX = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0"
	appCAliceY = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()

	b, err := b64.Decode(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func rfc7518AppendixCKeys(t *testing.T) (bob *ecdsa.PrivateKey, alice *ecdsa.PublicKey, aliceEPK string) {
	t.Helper()

	bob, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), mustB64(t, appCBobD))
	if err != nil {
		t.Fatal(err)
	}

	bobPub, _ := bob.PublicKey.Bytes()
	if want := append(append([]byte{4}, mustB64(t, appCBobX)...), mustB64(t, appCBobY)...); string(bobPub) != string(want) {
		t.Fatal("Appendix C: Bob's d does not match his published x/y")
	}

	alice, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(),
		append(append([]byte{4}, mustB64(t, appCAliceX)...), mustB64(t, appCAliceY)...))
	if err != nil {
		t.Fatal(err)
	}

	aliceEPK = `{"kty":"EC","crv":"P-256","x":"` + appCAliceX + `","y":"` + appCAliceY + `"}`

	return bob, alice, aliceEPK
}

func TestConcatKDFRFC7518AppendixC(t *testing.T) {
	bob, alice, _ := rfc7518AppendixCKeys(t)

	z, err := ecdhZ(bob, alice)
	if err != nil {
		t.Fatal(err)
	}

	// Appendix C: apu = "Alice", apv = "Bob", enc = A128GCM.
	got := concatKDF(z, "A128GCM", []byte("Alice"), []byte("Bob"), 128)
	if b64.Encode(got) != "VqqN6vgjbSBcIijNcacQGg" {
		t.Fatalf("derived key = %s, want VqqN6vgjbSBcIijNcacQGg", b64.Encode(got))
	}
}

func TestDecryptECDHESWithPartyInfoRFC7518AppendixC(t *testing.T) {
	bob, _, epk := rfc7518AppendixCKeys(t)
	cek, _ := b64.Decode("VqqN6vgjbSBcIijNcacQGg")
	hdr := `{"alg":"ECDH-ES","enc":"A128GCM","apu":"QWxpY2U","apv":"Qm9i","epk":` + epk + `}`
	tok := sealJWE(t, hdr, nil, cek, []byte(`{"sub":"bob"}`))

	dec, _ := NewECDHESDecrypter(bob)

	got, err := decryptClaims[appClaims](ctx(), tok, dec,
		WithAllowedKeyAlgorithms(ECDHES), WithAllowedContentAlgorithms(A128GCM))
	if err != nil || got.Subject != "bob" {
		t.Fatalf("Appendix C token: %v %+v", err, got)
	}

	// PartyUInfo/PartyVInfo are bound into the key: altering either breaks it.
	for _, h := range []string{
		`{"alg":"ECDH-ES","enc":"A128GCM","apv":"Qm9i","epk":` + epk + `}`,
		`{"alg":"ECDH-ES","enc":"A128GCM","apu":"Qm9i","apv":"QWxpY2U","epk":` + epk + `}`,
	} {
		if _, err := dec.Decrypt(ctx(), sealJWE(t, h, nil, cek, []byte(`{}`))); !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("party info %s: %v", h, err)
		}
	}
}

func TestDecryptECDHESWithPartyInfoKeyWrap(t *testing.T) {
	tk := newTestKeys(t)
	eph, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	z, _ := ecdhZ(eph, &tk.p256.PublicKey)

	kek := concatKDF(z, string(ECDHESA256KW), []byte("sender"), []byte("recipient"), 256)
	cek := mkKEK(32)
	wrapped, _ := aesKWWrap(kek, cek)

	epk, _ := FromECDSAPublicKey(&eph.PublicKey).MarshalJSON()
	hdr := `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","apu":"` + b64.Encode([]byte("sender")) +
		`","apv":"` + b64.Encode([]byte("recipient")) + `","epk":` + string(epk) + `}`
	tok := sealJWE(t, hdr, wrapped, cek, []byte(`{"sub":"kw"}`))

	dec, _ := NewECDHESDecrypter(tk.p256)
	if got, err := decryptClaims[appClaims](ctx(), tok, dec, jweAllow); err != nil || got.Subject != "kw" {
		t.Fatalf("ECDH-ES+A256KW with apu/apv: %v %+v", err, got)
	}
}

func TestDecryptECDHESRejectsBadPartyInfoAndEPK(t *testing.T) {
	tk := newTestKeys(t)
	dec, _ := NewECDHESDecrypter(tk.p256)

	// Using the recipient's own public key as "epk" makes Z computable here,
	// so each authentic token below would decrypt were it not for the single
	// defect under test.
	selfEPK, _ := FromECDSAPublicKey(&tk.p256.PublicKey).MarshalJSON()
	z, _ := ecdhZ(tk.p256, &tk.p256.PublicKey)
	cekFor := func(apu, apv string) []byte { return concatKDF(z, "A256GCM", []byte(apu), []byte(apv), 256) }

	if _, err := dec.Decrypt(ctx(), sealJWE(t, `{"alg":"ECDH-ES","enc":"A256GCM","apv":"Qm9i","epk":`+string(selfEPK)+`}`,
		nil, cekFor("", "Bob"), []byte(`{}`))); err != nil {
		t.Fatalf("control token failed: %v", err)
	}

	p384EPK, _ := FromECDSAPublicKey(&tk.p384.PublicKey).MarshalJSON()
	offCurve := `{"kty":"EC","crv":"P-256","x":"` + b64.Encode(make([]byte, 32)) + `","y":"` + b64.Encode(append(make([]byte, 31), 1)) + `"}`

	cases := []struct {
		name string
		hdr  string
		ek   []byte
		cek  []byte
	}{
		{"apu not base64url", `{"alg":"ECDH-ES","enc":"A256GCM","apu":"***","epk":` + string(selfEPK) + `}`, nil, cekFor("", "")},
		{"apv padded", `{"alg":"ECDH-ES","enc":"A256GCM","apv":"Qm9i=","epk":` + string(selfEPK) + `}`, nil, cekFor("", "Bob")},
		{"apu not a string", `{"alg":"ECDH-ES","enc":"A256GCM","apu":1,"epk":` + string(selfEPK) + `}`, nil, cekFor("", "")},
		{"encrypted_key with ECDH-ES", `{"alg":"ECDH-ES","enc":"A256GCM","epk":` + string(selfEPK) + `}`, []byte("unexpected"), cekFor("", "")},
		{"epk on another curve", `{"alg":"ECDH-ES","enc":"A256GCM","epk":` + string(p384EPK) + `}`, nil, mkKEK(32)},
		{"epk off curve", `{"alg":"ECDH-ES","enc":"A256GCM","epk":` + offCurve + `}`, nil, mkKEK(32)},
		{"epk OKP", `{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"OKP","crv":"Ed25519","x":"` + b64.Encode(tk.edPub) + `"}}`, nil, mkKEK(32)},
		{"epk missing", `{"alg":"ECDH-ES","enc":"A256GCM"}`, nil, mkKEK(32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dec.Decrypt(ctx(), sealJWE(t, tc.hdr, tc.ek, tc.cek, []byte(`{}`))); !errors.Is(err, ErrDecryptionFailed) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
