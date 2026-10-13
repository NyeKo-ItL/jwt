package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

func TestJWEDecrypterKeyID(t *testing.T) {
	tk := newTestKeys(t)

	d, _ := NewA256KWDecrypter(tk.hmac[:32], "kid-77")
	if d.KeyID() != "kid-77" {
		t.Fatalf("KeyID = %q", d.KeyID())
	}
}

func TestJWEMoreConstructorValidation(t *testing.T) {
	tk := newTestKeys(t)
	if _, err := NewA256KWDecrypter(make([]byte, 8), ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short KEK dec err = %v", err)
	}

	if _, err := NewRSAOAEP256Decrypter(nil, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil RSA dec err = %v", err)
	}

	if _, err := NewECDHESEncrypter(nil, ECDHES, A256GCM, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil EC enc err = %v", err)
	}

	if _, err := NewECDHESDecrypter(nil, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("nil EC dec err = %v", err)
	}
	// P-224 is a real curve but outside the JOSE set.
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewECDHESEncrypter(&p224.PublicKey, ECDHES, A256GCM, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("P-224 enc err = %v", err)
	}

	if _, err := NewECDHESDecrypter(p224, ""); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("P-224 dec err = %v", err)
	}

	_ = tk
}

func TestJWEECDHCurveMismatch(t *testing.T) {
	tk := newTestKeys(t)
	enc, _ := NewECDHESEncrypter(&tk.p256.PublicKey, ECDHES, A256GCM, "")
	compact, _ := enc.Encrypt([]byte("x"))
	// decrypt with a private key on a different curve
	dec, _ := NewECDHESDecrypter(tk.p384, "")
	if _, err := dec.Decrypt(jweCtx(), compact); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("curve-mismatch err = %v", err)
	}
}

func TestJWEEncryptClaimsMarshalError(t *testing.T) {
	tk := newTestKeys(t)

	enc, _ := NewA256KWEncrypter(tk.hmac[:32], A256GCM, "")
	if _, err := EncryptClaims(make(chan int), enc); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestJWEDirectWrapRejectsWrongLength(t *testing.T) {
	_, _, err := directWrapper{cek: make([]byte, 16)}.wrap(&jweHeader{Enc: A256GCM}, 32)
	if !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestAESKWLengthGuards(t *testing.T) {
	kek := make([]byte, 32)
	if _, err := aesKWWrap(kek, make([]byte, 12)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("wrap short err = %v", err)
	}

	if _, err := aesKWWrap(kek, make([]byte, 20)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("wrap non-multiple err = %v", err)
	}

	if _, err := aesKWUnwrap(kek, make([]byte, 16)); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("unwrap short err = %v", err)
	}

	if _, err := aesKWUnwrap(kek, make([]byte, 20)); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("unwrap non-multiple err = %v", err)
	}
	// bad KEK length surfaces from aes.NewCipher
	if _, err := aesKWWrap(make([]byte, 7), make([]byte, 16)); err == nil {
		t.Fatal("expected bad-KEK error from wrap")
	}

	if _, err := aesKWUnwrap(make([]byte, 7), make([]byte, 24)); err == nil {
		t.Fatal("expected bad-KEK error from unwrap")
	}
}

func TestAESKWRoundTripVaryingSizes(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}

	for _, n := range []int{16, 24, 32} {
		pt := make([]byte, n)
		for i := range pt {
			pt[i] = byte(255 - i)
		}

		wrapped, err := aesKWWrap(kek, pt)
		if err != nil {
			t.Fatalf("n=%d wrap: %v", n, err)
		}

		if len(wrapped) != n+8 {
			t.Fatalf("n=%d wrapped len = %d", n, len(wrapped))
		}

		back, err := aesKWUnwrap(kek, wrapped)
		if err != nil {
			t.Fatalf("n=%d unwrap: %v", n, err)
		}

		if string(back) != string(pt) {
			t.Fatalf("n=%d round trip mismatch", n)
		}
	}
}

func TestJWEECDHHeaderProblems(t *testing.T) {
	tk := newTestKeys(t)
	dec, _ := NewECDHESDecrypter(tk.p256, "")

	// missing epk
	noEPK := b64.Encode([]byte(`{"alg":"ECDH-ES","enc":"A256GCM"}`)) + ".." +
		b64.Encode([]byte("iv")) + "." + b64.Encode([]byte("ct")) + "." + b64.Encode([]byte("tag"))
	if _, err := dec.Decrypt(jweCtx(), noEPK); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("missing epk err = %v", err)
	}

	// epk present but structurally broken
	badEPK := b64.Encode([]byte(`{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}`)) +
		".." + b64.Encode([]byte("iv")) + "." + b64.Encode([]byte("ct")) + "." + b64.Encode([]byte("tag"))
	if _, err := dec.Decrypt(jweCtx(), badEPK); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("broken epk err = %v", err)
	}
}

type failingJWEWrapper struct{}

func (failingJWEWrapper) keyAlg() KeyAlgorithm { return Direct }
func (failingJWEWrapper) wrap(*jweHeader, int) ([]byte, []byte, error) {
	return nil, nil, errors.New("wrap failed")
}

type fixedJWEUnwrapper struct{ cek []byte }

func (fixedJWEUnwrapper) supports(KeyAlgorithm) bool                       { return true }
func (u fixedJWEUnwrapper) unwrap(*jweHeader, []byte, int) ([]byte, error) { return u.cek, nil }

func TestJWEErrorBranches(t *testing.T) {
	if _, err := newEncrypter(A256GCM, "", failingJWEWrapper{}); err != nil {
		t.Fatal(err)
	}
	enc := &encrypter{alg: Direct, enc: A256GCM, wrapper: failingJWEWrapper{}}
	if _, err := enc.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected wrapper error")
	}

	good := sealJWE(t, `{"alg":"dir","enc":"A256GCM"}`, nil, make([]byte, 32), []byte("x"))
	dec := &decrypter{unwrapper: fixedJWEUnwrapper{cek: []byte("bad")}}
	if _, err := dec.Decrypt(context.Background(), good); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("invalid CEK: %v", err)
	}
	parts := strings.Split(good, ".")
	for _, field := range []int{1, 2, 3, 4} {
		bad := append([]string(nil), parts...)
		bad[field] = "!"
		if _, err := (&decrypter{unwrapper: fixedJWEUnwrapper{cek: make([]byte, 32)}}).Decrypt(context.Background(), strings.Join(bad, ".")); !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("bad segment %d: %v", field, err)
		}
	}
	for _, field := range []int{2, 4} {
		bad := append([]string(nil), parts...)
		bad[field] = b64.Encode([]byte("short"))
		if _, err := (&decrypter{unwrapper: fixedJWEUnwrapper{cek: make([]byte, 32)}}).Decrypt(context.Background(), strings.Join(bad, ".")); !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("bad size %d: %v", field, err)
		}
	}

	badEPKObject := b64.Encode([]byte(`{"alg":"ECDH-ES","enc":"A256GCM","epk":[]}`)) + ".AA.AA.AA.AA"
	if _, _, err := parseJWEProtected(badEPKObject); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("bad epk object: %v", err)
	}
}

func TestJWENestedValidationErrors(t *testing.T) {
	validHeader := b64.Encode([]byte(`{"alg":"HS256"}`))
	validPayload := b64.Encode([]byte(`{}`))
	valid := validHeader + "." + validPayload + ".AA"
	cases := []string{
		"", "a.b", "!!!." + validPayload + ".AA", b64.Encode([]byte("[]")) + "." + validPayload + ".AA",
		b64.Encode([]byte(`{"alg":"none"}`)) + "." + validPayload + ".AA",
		validHeader + ".!!!.AA", validHeader + "." + b64.Encode([]byte("[]")) + ".AA", validHeader + "." + validPayload + ".",
	}
	for _, compact := range cases {
		if err := validateNestedJWS(compact); err == nil {
			t.Fatalf("validateNestedJWS(%q) unexpectedly succeeded", compact)
		}
	}
	if _, err := EncryptNestedJWT(valid, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("nil nested encrypter: %v", err)
	}
	if err := DecryptNestedJWT(context.Background(), valid, new(appClaims), nil, nil, NestedJWTPolicies{}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("nil nested decrypter: %v", err)
	}
}

func TestJWEECDHLowLevelErrorBranches(t *testing.T) {
	tk := newTestKeys(t)

	if _, _, err := (ecdhWrapper{pub: &tk.p256.PublicKey, alg: "unsupported"}).wrap(&jweHeader{Enc: A256GCM}, 32); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported ECDH wrapper: %v", err)
	}
	epk := FromECDSAPublicKey(&tk.p256.PublicKey)
	if _, err := (ecdhUnwrapper{priv: tk.p256}).unwrap(&jweHeader{Alg: ECDHESA256KW}, nil, 32); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("short ECDH-KW key: %v", err)
	}
	if _, err := (ecdhUnwrapper{priv: tk.p256}).unwrap(&jweHeader{Alg: ECDHESA256KW, EPK: &epk}, make([]byte, 40), 32); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("invalid ECDH-KW wrapped key: %v", err)
	}
	if _, err := (ecdhUnwrapper{priv: tk.p256}).unwrap(&jweHeader{Alg: "unsupported", EPK: &epk}, nil, 32); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("unsupported ECDH unwrap: %v", err)
	}

}
