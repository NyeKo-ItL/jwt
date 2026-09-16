package jwt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Known-answer tests against independent vectors (spec §7.2.1). Self round
// trips cannot catch a mistake shared by the encoder and decoder — the
// ECDH-ES+A256KW AlgorithmID bug is the precedent — so every algorithm
// implementation is also checked against published RFC outputs.

type joseVectors struct {
	JWS []struct {
		Source string          `json:"source"`
		Alg    Algorithm       `json:"alg"`
		Key    json.RawMessage `json:"key"`
		JWS    string          `json:"jws"`
		Clock  int64           `json:"clock"`
	} `json:"jws"`
	Unsecured struct {
		Source string `json:"source"`
		JWS    string `json:"jws"`
	} `json:"unsecured_jws"`
	JWE []struct {
		Source    string           `json:"source"`
		Alg       KeyAlgorithm     `json:"alg"`
		Enc       ContentAlgorithm `json:"enc"`
		Key       json.RawMessage  `json:"key"`
		JWE       string           `json:"jwe"`
		Plaintext string           `json:"plaintext"`
	} `json:"jwe"`
}

func loadJOSEVectors(t *testing.T) joseVectors {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "vectors", "jose.json"))
	if err != nil {
		t.Fatal(err)
	}

	var v joseVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	if len(v.JWS) == 0 || len(v.JWE) == 0 || v.Unsecured.JWS == "" {
		t.Fatal("vector file is incomplete")
	}

	return v
}

func TestKnownAnswerJWS(t *testing.T) {
	for _, vec := range loadJOSEVectors(t).JWS {
		t.Run(vec.Source, func(t *testing.T) {
			key, err := ParseKey(vec.Key)
			if err != nil {
				t.Fatalf("ParseKey: %v", err)
			}

			h, p, s, ok := split3(vec.JWS)
			if !ok {
				t.Fatal("vector is not a compact JWS")
			}

			v, err := key.verifierForAlg(vec.Alg)
			if err != nil {
				t.Fatalf("verifier: %v", err)
			}

			sig := mustB64(t, s)
			if err := v.Verify([]byte(h+"."+p), sig); err != nil {
				t.Fatalf("published signature does not verify: %v", err)
			}

			// Any single-bit change must break it.
			tampered := bytes.Clone(sig)
			tampered[len(tampered)/2] ^= 0x01

			if err := v.Verify([]byte(h+"."+p), tampered); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("tampered signature: %v", err)
			}

			// HMAC is deterministic: the built-in signer must reproduce the bytes.
			if key.Kty == KeyTypeOct {
				secret, _ := key.Secret()
				signer, _ := NewHMACSigner(vec.Alg, secret)

				got, _ := signer.Sign([]byte(h + "." + p))
				if !bytes.Equal(got, sig) {
					t.Fatalf("HMAC signer output differs from the RFC:\n got %x\nwant %x", got, sig)
				}
			}

			// Vectors whose payload is a JWT Claims Set also go through Parse.
			if vec.Clock == 0 {
				return
			}

			var claims struct {
				RegisteredClaims
				IsRoot bool `json:"http://example.com/is_root"`
			}

			err = Parse(ctx(), vec.JWS, &claims, NewKeySet(key),
				WithAllowedAlgorithms(vec.Alg),
				WithIssuer("joe"),
				WithClock(func() time.Time { return time.Unix(vec.Clock, 0) }))
			if err != nil || !claims.IsRoot || claims.ExpiresAt.Unix() != 1300819380 {
				t.Fatalf("Parse: %v %+v", err, claims)
			}

			// ... and are rejected once expired.
			err = Parse(ctx(), vec.JWS, &claims, NewKeySet(key), WithAllowedAlgorithms(vec.Alg))
			if !errors.Is(err, ErrExpired) {
				t.Fatalf("expired vector: %v", err)
			}
		})
	}
}

func TestKnownAnswerUnsecuredJWSRejected(t *testing.T) {
	vec := loadJOSEVectors(t).Unsecured
	keys := StaticKeyProvider(FromHMACSecret(make([]byte, 32)))

	for _, allowed := range [][]Algorithm{{HS256}, {"none", HS256}} {
		var c RegisteredClaims
		if err := Parse(ctx(), vec.JWS, &c, keys, WithAllowedAlgorithms(allowed...)); !errors.Is(err, ErrMalformedToken) && !errors.Is(err, ErrAlgorithmNotAllowed) {
			t.Fatalf("%s accepted with allowlist %v: %v", vec.Source, allowed, err)
		}
	}
}

func TestKnownAnswerJWE(t *testing.T) {
	for _, vec := range loadJOSEVectors(t).JWE {
		t.Run(vec.Source, func(t *testing.T) {
			key, err := ParseKey(vec.Key)
			if err != nil {
				t.Fatalf("ParseKey: %v", err)
			}

			cek, err := key.Secret()
			if err != nil {
				t.Fatal(err)
			}

			dec, err := NewDirectDecrypter(cek, key.Kid)
			if err != nil {
				t.Fatal(err)
			}

			got, err := dec.Decrypt(ctx(), vec.JWE)
			if err != nil || string(got) != vec.Plaintext {
				t.Fatalf("Decrypt: %v\n got %q\nwant %q", err, got, vec.Plaintext)
			}

			_, hdr, err := parseJWEProtected(vec.JWE)
			if err != nil || hdr.Alg != vec.Alg || hdr.Enc != vec.Enc || hdr.Kid != key.Kid {
				t.Fatalf("header: %v %+v", err, hdr)
			}
		})
	}
}

func TestKnownAnswerAESKeyWrapRFC3394(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")

	cases := []struct{ section, keyData, ciphertext string }{
		{"4.3", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
		{"4.6", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
	}
	for _, tc := range cases {
		keyData, _ := hex.DecodeString(tc.keyData)
		want, _ := hex.DecodeString(tc.ciphertext)

		got, err := aesKWWrap(kek, keyData)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("RFC 3394 §%s wrap = %X (%v), want %X", tc.section, got, err, want)
		}

		back, err := aesKWUnwrap(kek, want)
		if err != nil || !bytes.Equal(back, keyData) {
			t.Fatalf("RFC 3394 §%s unwrap = %X (%v)", tc.section, back, err)
		}
	}
}

func TestKnownAnswerThumbprintRFC8037(t *testing.T) {
	k, err := ParseKey([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037X + `"}`))
	if err != nil {
		t.Fatal(err)
	}

	const want = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" // RFC 8037 Appendix A.3

	if got, err := Thumbprint(k); err != nil || got != want {
		t.Fatalf("Thumbprint = %q (%v), want %q", got, err, want)
	}

	if got, err := ThumbprintBytes(KeyTypeOKP, mustB64(t, rfc8037X)); err != nil || got != want {
		t.Fatalf("ThumbprintBytes = %q (%v), want %q", got, err, want)
	}
}
