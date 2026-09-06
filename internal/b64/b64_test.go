package b64_test

import (
	"bytes"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("f"),
		[]byte("fo"),
		[]byte("foo"),
		[]byte("foob"),
		[]byte("fooba"),
		[]byte("foobar"),
		{0x00, 0xff, 0x10, 0x7e, 0x7f},
	}
	for _, in := range cases {
		enc := b64.Encode(in)
		if bytes.ContainsAny([]byte(enc), "=+/") {
			t.Fatalf("Encode(%q) = %q, contains padding or non-url alphabet", in, enc)
		}
		out, err := b64.Decode(enc)
		if err != nil {
			t.Fatalf("Decode(%q): %v", enc, err)
		}
		if len(in) == 0 && len(out) == 0 {
			continue
		}
		if !bytes.Equal(in, out) {
			t.Fatalf("round trip mismatch: in=%q out=%q", in, out)
		}
	}
}

func TestDecodeRejectsPadding(t *testing.T) {
	// "foo" -> "Zm9v"; "fo" -> "Zm8" (RawURLEncoding); padded form is invalid.
	if _, err := b64.Decode("Zm8="); err == nil {
		t.Fatal("Decode accepted padded input")
	}
}

func TestDecodeRejectsNonAlphabet(t *testing.T) {
	// Note: Go's base64 decoder silently ignores \r and \n, so those are not
	// tested here; the standard-alphabet '+' and '/' are rejected by the
	// URL-safe alphabet.
	for _, s := range []string{"a b", "****", "Zm+8", "Zm/8"} {
		if _, err := b64.Decode(s); err == nil {
			t.Fatalf("Decode(%q) accepted invalid input", s)
		}
	}
}

func TestEncodeEmpty(t *testing.T) {
	if got := b64.Encode(nil); got != "" {
		t.Fatalf("Encode(nil) = %q, want empty", got)
	}
}
