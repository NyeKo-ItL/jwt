package jwt

import (
	"errors"
	"testing"
)

func TestHMACRoundTrip(t *testing.T) {
	key := make([]byte, 64)
	for _, alg := range []Algorithm{HS256, HS384, HS512} {
		s, err := NewHMACSigner(alg, key, "h1")
		if err != nil {
			t.Fatalf("%s: NewHMACSigner: %v", alg, err)
		}
		if s.Algorithm() != alg || s.KeyID() != "h1" {
			t.Fatalf("%s: getters wrong", alg)
		}
		sig, err := s.Sign([]byte("header.payload"))
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}
		v, err := NewHMACVerifier(alg, key, "h1")
		if err != nil {
			t.Fatalf("%s: NewHMACVerifier: %v", alg, err)
		}
		if err := v.Verify([]byte("header.payload"), sig); err != nil {
			t.Fatalf("%s: Verify: %v", alg, err)
		}
		if v.Algorithm() != alg {
			t.Fatalf("%s: verifier alg wrong", alg)
		}
	}
}

func TestHMACVerifyRejectsTampered(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewHMACSigner(HS256, key, "")
	v, _ := NewHMACVerifier(HS256, key, "")
	sig, _ := s.Sign([]byte("a.b"))

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if err := v.Verify([]byte("a.b"), tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered sig err = %v", err)
	}
	if err := v.Verify([]byte("other"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong input err = %v", err)
	}

	other := make([]byte, 32)
	other[0] = 1
	v2, _ := NewHMACVerifier(HS256, other, "")
	if err := v2.Verify([]byte("a.b"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong key err = %v", err)
	}
}

func TestHMACRejectsShortKey(t *testing.T) {
	cases := []struct {
		alg Algorithm
		n   int
	}{
		{HS256, 31},
		{HS384, 47},
		{HS512, 63},
	}
	for _, c := range cases {
		if _, err := NewHMACSigner(c.alg, make([]byte, c.n), ""); !errors.Is(err, ErrWeakKey) {
			t.Fatalf("%s/%d: signer err = %v, want ErrWeakKey", c.alg, c.n, err)
		}
		if _, err := NewHMACVerifier(c.alg, make([]byte, c.n), ""); !errors.Is(err, ErrWeakKey) {
			t.Fatalf("%s/%d: verifier err = %v, want ErrWeakKey", c.alg, c.n, err)
		}
	}
}

func TestHMACRejectsWrongAlgorithm(t *testing.T) {
	if _, err := NewHMACSigner(ES256, make([]byte, 64), ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := NewHMACVerifier("bogus", make([]byte, 64), ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}
