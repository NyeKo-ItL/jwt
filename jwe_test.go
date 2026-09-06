package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

func jweCtx() context.Context { return context.Background() }

func mkKEK(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestJWERoundTripAllAlgorithms(t *testing.T) {
	tk := newTestKeys(t)
	contents := []ContentAlgorithm{A128GCM, A192GCM, A256GCM}

	type factory struct {
		name string
		enc  func(ContentAlgorithm) (Encrypter, error)
		dec  func() (Decrypter, error)
	}
	factories := []factory{
		{
			name: "RSA-OAEP-256",
			enc: func(c ContentAlgorithm) (Encrypter, error) {
				return NewRSAOAEP256Encrypter(&tk.rsa2048.PublicKey, c, "r1")
			},
			dec: func() (Decrypter, error) { return NewRSAOAEP256Decrypter(tk.rsa2048, "r1") },
		},
		{
			name: "A256KW",
			enc:  func(c ContentAlgorithm) (Encrypter, error) { return NewA256KWEncrypter(tk.hmac[:32], c, "k1") },
			dec:  func() (Decrypter, error) { return NewA256KWDecrypter(tk.hmac[:32], "k1") },
		},
		{
			name: "ECDH-ES",
			enc: func(c ContentAlgorithm) (Encrypter, error) {
				return NewECDHESEncrypter(&tk.p256.PublicKey, ECDHES, c, "e1")
			},
			dec: func() (Decrypter, error) { return NewECDHESDecrypter(tk.p256, "e1") },
		},
		{
			name: "ECDH-ES+A256KW",
			enc: func(c ContentAlgorithm) (Encrypter, error) {
				return NewECDHESEncrypter(&tk.p384.PublicKey, ECDHESA256KW, c, "e2")
			},
			dec: func() (Decrypter, error) { return NewECDHESDecrypter(tk.p384, "e2") },
		},
	}

	msg := []byte(`{"hello":"world","n":42}`)
	for _, f := range factories {
		for _, c := range contents {
			t.Run(f.name+"/"+string(c), func(t *testing.T) {
				enc, err := f.enc(c)
				if err != nil {
					t.Fatalf("new encrypter: %v", err)
				}
				if enc.ContentAlgorithm() != c {
					t.Fatalf("ContentAlgorithm() = %s", enc.ContentAlgorithm())
				}
				compact, err := enc.Encrypt(msg)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if n := strings.Count(compact, "."); n != 4 {
					t.Fatalf("compact JWE has %d dots, want 4", n)
				}
				dec, err := f.dec()
				if err != nil {
					t.Fatalf("new decrypter: %v", err)
				}
				got, err := dec.Decrypt(jweCtx(), compact)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				if string(got) != string(msg) {
					t.Fatalf("plaintext = %q, want %q", got, msg)
				}
			})
		}
	}
}

func TestJWEDirectRoundTrip(t *testing.T) {
	for _, c := range []ContentAlgorithm{A128GCM, A192GCM, A256GCM} {
		cek := mkKEK(contentKeyLen(c))
		enc, err := NewDirectEncrypter(cek, c, "d1")
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if enc.KeyAlgorithm() != Direct || enc.KeyID() != "d1" {
			t.Fatalf("%s: getters wrong", c)
		}
		compact, err := enc.Encrypt([]byte("secret payload"))
		if err != nil {
			t.Fatalf("%s: encrypt: %v", c, err)
		}
		// encrypted_key segment must be empty for "dir"
		if parts := strings.Split(compact, "."); parts[1] != "" {
			t.Fatalf("%s: dir encrypted_key not empty: %q", c, parts[1])
		}
		dec, err := NewDirectDecrypter(cek, "d1")
		if err != nil {
			t.Fatal(err)
		}
		got, err := dec.Decrypt(jweCtx(), compact)
		if err != nil || string(got) != "secret payload" {
			t.Fatalf("%s: decrypt: %q %v", c, got, err)
		}
	}
}

func TestJWEFailsClosedOnTamper(t *testing.T) {
	tk := newTestKeys(t)
	enc, _ := NewA256KWEncrypter(tk.hmac[:32], A256GCM, "")
	dec, _ := NewA256KWDecrypter(tk.hmac[:32], "")
	compact, err := enc.Encrypt([]byte("top secret"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")

	mutate := func(i int, s string) string {
		cp := append([]string(nil), parts...)
		cp[i] = s
		return strings.Join(cp, ".")
	}

	// flip a byte in the ciphertext
	ctBytes, _ := b64.Decode(parts[3])
	ctBytes[0] ^= 0xff
	if _, err := dec.Decrypt(jweCtx(), mutate(3, b64.Encode(ctBytes))); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered ciphertext err = %v", err)
	}
	// flip a byte in the tag
	tagBytes, _ := b64.Decode(parts[4])
	tagBytes[0] ^= 0xff
	if _, err := dec.Decrypt(jweCtx(), mutate(4, b64.Encode(tagBytes))); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered tag err = %v", err)
	}
	// tamper the protected header (breaks the AAD)
	if _, err := dec.Decrypt(jweCtx(), mutate(0, b64.Encode([]byte(`{"alg":"A256KW","enc":"A256GCM","x":1}`)))); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered header err = %v", err)
	}
}

func TestJWERejectsWrongRecipient(t *testing.T) {
	tk := newTestKeys(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	enc, _ := NewRSAOAEP256Encrypter(&tk.rsa2048.PublicKey, A256GCM, "")
	compact, _ := enc.Encrypt([]byte("hi"))

	wrong, _ := NewRSAOAEP256Decrypter(other, "")
	if _, err := wrong.Decrypt(jweCtx(), compact); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("wrong key err = %v", err)
	}

	// a decrypter for a different alg family must also refuse
	kw, _ := NewA256KWDecrypter(tk.hmac[:32], "")
	if _, err := kw.Decrypt(jweCtx(), compact); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("alg-mismatch err = %v", err)
	}
}

func TestJWEMalformedCompact(t *testing.T) {
	tk := newTestKeys(t)
	dec, _ := NewA256KWDecrypter(tk.hmac[:32], "")
	for _, bad := range []string{
		"",
		"a.b.c.d",     // 4 segments
		"a.b.c.d.e.f", // 6 segments
		"!!!.b.c.d.e", // bad b64 header
		b64.Encode([]byte("not json")) + ".b.c.d.e",
		b64.Encode([]byte(`{"alg":"A256KW","enc":"BOGUS"}`)) + ".b.c.d.e",
		b64.Encode([]byte(`{"alg":"dir","enc":"A256GCM"}`)) + ".b.c.d.e", // alg not supported by this decrypter
	} {
		if _, err := dec.Decrypt(jweCtx(), bad); !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("Decrypt(%.20q) err = %v", bad, err)
		}
	}
}

func TestJWEConstructorValidation(t *testing.T) {
	tk := newTestKeys(t)

	if _, err := NewRSAOAEP256Encrypter(&tk.rsa1024.PublicKey, A256GCM, ""); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("weak RSA enc err = %v", err)
	}
	if _, err := NewRSAOAEP256Decrypter(tk.rsa1024, ""); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("weak RSA dec err = %v", err)
	}
	if _, err := NewRSAOAEP256Encrypter(nil, A256GCM, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil RSA err = %v", err)
	}
	if _, err := NewA256KWEncrypter(make([]byte, 16), A256GCM, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short KEK err = %v", err)
	}
	if _, err := NewDirectEncrypter(make([]byte, 16), A256GCM, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("dir key/enc mismatch err = %v", err)
	}
	if _, err := NewDirectDecrypter(make([]byte, 20), ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("dir dec bad len err = %v", err)
	}
	if _, err := NewECDHESEncrypter(&tk.p256.PublicKey, A256KW, A256GCM, ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("ecdh bad alg err = %v", err)
	}
	if _, err := NewRSAOAEP256Encrypter(&tk.rsa2048.PublicKey, "A999GCM", ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("bad content alg err = %v", err)
	}
}

func TestDirCekLengthMustMatchContent(t *testing.T) {
	tk := newTestKeys(t)
	// A 32-byte dir key is valid to construct, but a token claiming A128GCM
	// must be refused because the CEK length no longer matches.
	dec, err := NewDirectDecrypter(tk.hmac[:32], "")
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := NewDirectEncrypter(tk.hmac[:16], A128GCM, "")
	compact, _ := enc.Encrypt([]byte("x"))
	if _, err := dec.Decrypt(jweCtx(), compact); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("CEK-length mismatch err = %v", err)
	}
}

func TestEncryptDecryptClaims(t *testing.T) {
	tk := newTestKeys(t)
	enc, _ := NewECDHESEncrypter(&tk.p256.PublicKey, ECDHESA256KW, A256GCM, "e1")
	dec, _ := NewECDHESDecrypter(tk.p256, "e1")

	in := Claims[appClaims]{
		RegisteredClaims: RegisteredClaims{
			Issuer:    "enc-issuer",
			Subject:   "u9",
			Audience:  Audience{"aud9"},
			ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
		},
		Custom: appClaims{Scope: "read"},
	}
	compact, err := EncryptClaims(in, enc)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecryptClaims[appClaims](jweCtx(), compact, dec,
		WithIssuer("enc-issuer"), WithAudience("aud9"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "u9" || out.Custom.Scope != "read" {
		t.Fatalf("claims = %+v", out)
	}

	// claim validation still runs after decryption
	expired := in
	expired.ExpiresAt = NewNumericDate(time.Now().Add(-time.Hour))
	badCompact, _ := EncryptClaims(expired, enc)
	if _, err := DecryptClaims[appClaims](jweCtx(), badCompact, dec); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired enc claims err = %v", err)
	}

	// wrong issuer
	if _, err := DecryptClaims[appClaims](jweCtx(), compact, dec, WithIssuer("nope")); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("issuer err = %v", err)
	}
}

func TestEncryptDecryptClaimsNilAndGarbage(t *testing.T) {
	tk := newTestKeys(t)
	dec, _ := NewA256KWDecrypter(tk.hmac[:32], "")

	if _, err := EncryptClaims(Claims[appClaims]{}, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("nil encrypter err = %v", err)
	}
	if _, err := DecryptClaims[appClaims](jweCtx(), "x.y.z.a.b", nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("nil decrypter err = %v", err)
	}
	if _, err := DecryptClaims[appClaims](jweCtx(), "garbage", dec); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("garbage err = %v", err)
	}

	// valid JWE whose plaintext is not a JSON object
	enc, _ := NewA256KWEncrypter(tk.hmac[:32], A256GCM, "")
	compact, _ := enc.Encrypt([]byte("not-json"))
	if _, err := DecryptClaims[appClaims](jweCtx(), compact, dec); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("non-json plaintext err = %v", err)
	}
}
