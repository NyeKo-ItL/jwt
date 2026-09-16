package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// ---- RFC 7519 §4.1.3 "aud": reject a token not addressed to this principal -----

func TestParseAudienceEnforcement(t *testing.T) {
	key, keys := strictFixture(t)
	algs := WithAllowedAlgorithms(HS256)

	cases := []struct {
		name    string
		payload string
		opts    []ParseOption
		wantErr error
	}{
		// aud present, nothing configured: the principal cannot identify
		// itself, so the JWT MUST be rejected.
		{"string aud, no audience configured", `{"aud":"other-service"}`, nil, ErrAudienceMismatch},
		{"array aud, no audience configured", `{"aud":["a","b"]}`, nil, ErrAudienceMismatch},
		{"empty array aud, no audience configured", `{"aud":[]}`, nil, ErrAudienceMismatch},
		{"empty string aud, no audience configured", `{"aud":""}`, nil, ErrAudienceMismatch},

		// aud absent: nothing to match, token accepted unless WithAudience.
		{"no aud, no audience configured", `{}`, nil, nil},
		{"null aud, no audience configured", `{"aud":null}`, nil, nil},
		{"no aud, audience configured", `{}`, []ParseOption{WithAudience("api")}, ErrAudienceMismatch},
		{"empty array aud, audience configured", `{"aud":[]}`, []ParseOption{WithAudience("api")}, ErrAudienceMismatch},

		// aud present and configured.
		{"string match", `{"aud":"api"}`, []ParseOption{WithAudience("api")}, nil},
		{"array member match", `{"aud":["x","api"]}`, []ParseOption{WithAudience("api")}, nil},
		{"no match", `{"aud":["x","y"]}`, []ParseOption{WithAudience("api")}, ErrAudienceMismatch},
		{"match is case-sensitive", `{"aud":"API"}`, []ParseOption{WithAudience("api")}, ErrAudienceMismatch},
		{"no prefix matching", `{"aud":"api-v2"}`, []ParseOption{WithAudience("api")}, ErrAudienceMismatch},

		// explicit opt-out.
		{"opt-out accepts foreign aud", `{"aud":"other-service"}`, []ParseOption{WithoutAudienceCheck()}, nil},
		{"opt-out via struct", `{"aud":"other-service"}`, []ParseOption{ParseOptions{SkipAudienceCheck: true}}, nil},
		{"WithAudience still wins over opt-out", `{"aud":"other"}`, []ParseOption{WithoutAudienceCheck(), WithAudience("api")}, ErrAudienceMismatch},
		{"opt-out order does not matter", `{"aud":"other"}`, []ParseOption{WithAudience("api"), WithoutAudienceCheck()}, ErrAudienceMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := signRawHS256(key, `{"alg":"HS256"}`, tc.payload)

			_, err := parse[appClaims](ctx(), tok, keys, append([]ParseOption{algs}, tc.opts...)...)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDecryptClaimsAudienceEnforcement(t *testing.T) {
	cek := make([]byte, 32)
	enc, _ := NewDirectEncrypter(cek, A256GCM)
	dec, _ := NewDirectDecrypter(cek)

	tok, err := EncryptClaims(RegisteredClaims{Audience: Audience{"other"}}, enc)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decryptClaims[appClaims](ctx(), tok, dec, jweAllow); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("JWE with foreign aud and no audience: %v", err)
	}

	if _, err := decryptClaims[appClaims](ctx(), tok, dec, jweAllow, WithoutAudienceCheck()); err != nil {
		t.Fatalf("JWE with opt-out: %v", err)
	}
}

// ---- RFC 7517 §4.2–4.4 "use" / "key_ops" / "alg" on the verification key --------

func jwkWith(t *testing.T, base Key, extra map[string]any) Key {
	t.Helper()

	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	for k, v := range extra {
		m[k] = v
	}

	raw, _ = json.Marshal(m)

	k, err := ParseKey(raw)
	if err != nil {
		t.Fatalf("ParseKey(%s): %v", raw, err)
	}

	return k
}

func TestParseHonorsJWKUsageConstraints(t *testing.T) {
	tk := newTestKeys(t)
	signer, _ := NewEd25519Signer(tk.edPriv)
	tok, _ := Sign(appClaims{}, signer)
	base := FromEd25519PublicKey(tk.edPub)

	cases := []struct {
		name  string
		extra map[string]any
		ok    bool
	}{
		{"no constraints", nil, true},
		{"use sig", map[string]any{"use": "sig"}, true},
		{"use enc", map[string]any{"use": "enc"}, false},
		{"use unknown value", map[string]any{"use": "wrap"}, false},
		{"alg matches header", map[string]any{"alg": "Ed25519"}, true},
		{"alg for another algorithm", map[string]any{"alg": "ES256"}, false},
		{"alg for key management", map[string]any{"alg": "ECDH-ES"}, false},
		{"key_ops verify", map[string]any{"key_ops": []string{"verify"}}, true},
		{"key_ops sign+verify", map[string]any{"key_ops": []string{"sign", "verify"}}, true},
		{"key_ops sign only", map[string]any{"key_ops": []string{"sign"}}, false},
		{"key_ops encrypt", map[string]any{"key_ops": []string{"encrypt", "wrapKey"}}, false},
		{"all consistent", map[string]any{"use": "sig", "alg": "Ed25519", "key_ops": []string{"verify"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := jwkWith(t, base, tc.extra)

			_, err := parse[appClaims](ctx(), tok, StaticKeyProvider(k), WithAllowedAlgorithms(Ed25519))
			if tc.ok && err != nil {
				t.Fatalf("err = %v", err)
			}

			if !tc.ok && !errors.Is(err, ErrKeyUsage) {
				t.Fatalf("err = %v, want ErrKeyUsage", err)
			}
		})
	}
}

func TestHMACKeyUsageConstraints(t *testing.T) {
	key := newTestKeys(t).hmac
	signer, _ := NewHMACSigner(HS384, key)
	tok, _ := Sign(appClaims{}, signer)

	k := FromHMACSecret(key)
	k.Alg = string(HS256) // key registered for HS256 only

	if _, err := parse[appClaims](ctx(), tok, StaticKeyProvider(k), WithAllowedAlgorithms(HS256, HS384)); !errors.Is(err, ErrKeyUsage) {
		t.Fatalf("HS256-only key verified HS384: %v", err)
	}
}

func TestKeyVerifierRespectsUsage(t *testing.T) {
	tk := newTestKeys(t)
	k := FromEd25519PublicKey(tk.edPub)
	k.Alg, k.Use = string(Ed25519), "enc"

	if _, err := k.Verifier(); !errors.Is(err, ErrKeyUsage) {
		t.Fatalf("Key.Verifier on a use=enc key: %v", err)
	}
}

func TestKeyOpsRoundTripAndValidation(t *testing.T) {
	tk := newTestKeys(t)
	k := jwkWith(t, FromEd25519PublicKey(tk.edPub, "o"), map[string]any{"key_ops": []string{"verify"}})

	if len(k.KeyOps) != 1 || k.KeyOps[0] != "verify" {
		t.Fatalf("KeyOps = %v", k.KeyOps)
	}

	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}

	back, err := ParseKey(raw)
	if err != nil || len(back.KeyOps) != 1 {
		t.Fatalf("round trip: %s %v %v", raw, back.KeyOps, err)
	}

	// RFC 7517 §4.3: "Duplicate key operation values MUST NOT be present".
	dup := []byte(`{"kty":"OKP","crv":"Ed25519","x":"` + b64.Encode(tk.edPub) + `","key_ops":["verify","verify"]}`)
	if _, err := ParseKey(dup); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("duplicate key_ops: %v", err)
	}

	// RFC 7517 §4.3: use and key_ops, if both present, MUST be consistent.
	inconsistent := []byte(`{"kty":"OKP","crv":"Ed25519","x":"` + b64.Encode(tk.edPub) + `","use":"sig","key_ops":["encrypt"]}`)
	if _, err := ParseKey(inconsistent); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("inconsistent use/key_ops: %v", err)
	}
}

// ---- RFC 7518 §6.2.1.2 / §6.3.1.1: one canonical encoding per key -----------------

func TestParseKeyRejectsNonCanonicalMaterial(t *testing.T) {
	tk := newTestKeys(t)

	rsaK := FromRSAPublicKey(&tk.rsa2048.PublicKey)
	n, e := b64.Encode(rsaK.n), b64.Encode(rsaK.e)

	ecK := FromECDSAPublicKey(&tk.p256.PublicKey)
	x, y := b64.Encode(ecK.x), b64.Encode(ecK.y)

	padded := func(b []byte) string { return b64.Encode(append([]byte{0}, b...)) }
	short := func(b []byte) string { return b64.Encode(b[1:]) }

	cases := map[string]string{
		"RSA n leading zero":      `{"kty":"RSA","n":"` + padded(rsaK.n) + `","e":"` + e + `"}`,
		"RSA e leading zero":      `{"kty":"RSA","n":"` + n + `","e":"` + padded(rsaK.e) + `"}`,
		"RSA e zero":              `{"kty":"RSA","n":"` + n + `","e":"AA"}`,
		"EC x short":              `{"kty":"EC","crv":"P-256","x":"` + short(ecK.x) + `","y":"` + y + `"}`,
		"EC y long":               `{"kty":"EC","crv":"P-256","x":"` + x + `","y":"` + padded(ecK.y) + `"}`,
		"EC P-384 with P-256 len": `{"kty":"EC","crv":"P-384","x":"` + x + `","y":"` + y + `"}`,
		"OKP Ed25519 short x":     `{"kty":"OKP","crv":"Ed25519","x":"` + b64.Encode(tk.edPub[1:]) + `"}`,
		"duplicate member":        `{"kty":"RSA","n":"` + n + `","e":"` + e + `","e":"` + e + `"}`,
		"mis-cased member":        `{"KTY":"RSA","n":"` + n + `","e":"` + e + `"}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKey([]byte(doc)); !errors.Is(err, ErrMalformedKey) {
				t.Fatalf("err = %v, want ErrMalformedKey", err)
			}
		})
	}
}

func TestCanonicalKeyMaterialStillParses(t *testing.T) {
	tk := newTestKeys(t)

	for _, k := range []Key{
		FromRSAPublicKey(&tk.rsa2048.PublicKey),
		FromECDSAPublicKey(&tk.p256.PublicKey),
		FromECDSAPublicKey(&tk.p384.PublicKey),
		FromECDSAPublicKey(&tk.p521.PublicKey),
		FromEd25519PublicKey(tk.edPub),
	} {
		raw, _ := json.Marshal(k)
		if _, err := ParseKey(raw); err != nil {
			t.Fatalf("ParseKey(%s): %v", raw, err)
		}
	}

	// A P-256 coordinate whose big-endian form starts with 0x00 must still be
	// accepted at its full 32-byte length (~1 key in 128 has one).
	for range 4000 {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		k := FromECDSAPublicKey(&priv.PublicKey)
		if k.x[0] != 0 && k.y[0] != 0 {
			continue
		}

		raw, _ := json.Marshal(k)
		if _, err := ParseKey(raw); err != nil {
			t.Fatalf("full-length coordinate with leading zero rejected: %v", err)
		}

		return
	}

	t.Fatal("no P-256 key with a leading-zero coordinate generated")
}

func TestPublicKeyRequiresFullLengthCoordinates(t *testing.T) {
	tk := newTestKeys(t)
	k := FromECDSAPublicKey(&tk.p256.PublicKey)
	k.x = k.x[1:] // bypass ParseKey: constructed in-package

	if _, err := k.PublicKey(); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short coordinate accepted by PublicKey: %v", err)
	}
}

func TestThumbprintIsUniquePerKey(t *testing.T) {
	// With non-canonical encodings rejected, the RFC 7638 thumbprint of a
	// parsed key is a function of the key alone (§3.3 relies on this).
	tk := newTestKeys(t)
	k := FromECDSAPublicKey(&tk.p256.PublicKey)
	raw, _ := json.Marshal(k)

	parsed, err := ParseKey(raw)
	if err != nil {
		t.Fatal(err)
	}

	a, _ := Thumbprint(k)
	b, _ := Thumbprint(parsed)

	if a != b {
		t.Fatalf("thumbprint changed across a JSON round trip: %s vs %s", a, b)
	}
}
