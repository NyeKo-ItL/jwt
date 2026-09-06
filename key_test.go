package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
)

func TestFromRSAPublicKeyRoundTrip(t *testing.T) {
	tk := newTestKeys(t)
	k := FromRSAPublicKey(&tk.rsa2048.PublicKey, "r1")
	if k.Kty != KeyTypeRSA || k.Kid != "r1" {
		t.Fatalf("unexpected key header: %+v", k)
	}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	rp, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey returned %T", pub)
	}
	if rp.N.Cmp(tk.rsa2048.N) != 0 || rp.E != tk.rsa2048.E {
		t.Fatal("RSA public key material mismatch after round trip")
	}
}

func TestFromECDSAPublicKeyRoundTrip(t *testing.T) {
	tk := newTestKeys(t)
	for _, priv := range []*ecdsa.PrivateKey{tk.p256, tk.p384, tk.p521} {
		k := FromECDSAPublicKey(&priv.PublicKey, "e1")
		pub, err := k.PublicKey()
		if err != nil {
			t.Fatalf("%s: %v", priv.Curve.Params().Name, err)
		}
		if !pub.(*ecdsa.PublicKey).Equal(&priv.PublicKey) {
			t.Fatalf("%s: EC key material mismatch", priv.Curve.Params().Name)
		}
	}
}

func TestFromEd25519PublicKeyRoundTrip(t *testing.T) {
	tk := newTestKeys(t)
	k := FromEd25519PublicKey(tk.edPub, "o1")
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !pub.(ed25519.PublicKey).Equal(tk.edPub) {
		t.Fatal("Ed25519 public key mismatch after round trip")
	}
}

func TestKeyJSONRoundTrip(t *testing.T) {
	tk := newTestKeys(t)
	keys := []Key{
		FromRSAPublicKey(&tk.rsa2048.PublicKey, "r1"),
		FromECDSAPublicKey(&tk.p256.PublicKey, "e1"),
		FromEd25519PublicKey(tk.edPub, "o1"),
	}
	for _, k := range keys {
		raw, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("%s: marshal: %v", k.Kty, err)
		}
		var back Key
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("%s: unmarshal: %v", k.Kty, err)
		}
		if _, err := back.PublicKey(); err != nil {
			t.Fatalf("%s: PublicKey after JSON round trip: %v", k.Kty, err)
		}
	}
}

func TestOctKeyDoesNotMarshal(t *testing.T) {
	k := FromHMACSecret([]byte("0123456789abcdef0123456789abcdef"), "h1")
	if _, err := json.Marshal(k); !errors.Is(err, ErrOctNotServable) {
		t.Fatalf("Marshal(oct) error = %v, want ErrOctNotServable", err)
	}
	secret, err := k.Secret()
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "0123456789abcdef0123456789abcdef" {
		t.Fatal("Secret returned wrong bytes")
	}
}

func TestSecretRejectsNonOct(t *testing.T) {
	tk := newTestKeys(t)
	k := FromRSAPublicKey(&tk.rsa2048.PublicKey, "r1")
	if _, err := k.Secret(); !errors.Is(err, ErrKeyTypeMismatch) {
		t.Fatalf("Secret on RSA key = %v, want ErrKeyTypeMismatch", err)
	}
}

func TestKeyJSONUnmarshalRejectsBadBase64(t *testing.T) {
	var k Key
	err := json.Unmarshal([]byte(`{"kty":"RSA","n":"!!!!","e":"AQAB"}`), &k)
	if err == nil {
		t.Fatal("expected error for non-base64url n")
	}
}

func TestPublicKeyMalformed(t *testing.T) {
	cases := []Key{
		{Kty: KeyTypeRSA},
		{Kty: KeyTypeEC, crv: "P-256"},
		{Kty: KeyTypeEC, crv: "bogus", x: []byte{1}, y: []byte{2}},
		{Kty: KeyTypeOKP, crv: "Ed25519", x: []byte{1, 2, 3}},
		{Kty: KeyTypeOKP, crv: "X25519"},
		{Kty: "wat"},
	}
	for i, k := range cases {
		if _, err := k.PublicKey(); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("case %d: PublicKey err = %v, want ErrMalformedKey", i, err)
		}
	}
}

func TestKeyVerifierUsesOwnAlg(t *testing.T) {
	tk := newTestKeys(t)
	k := FromECDSAPublicKey(&tk.p256.PublicKey, "e1")
	k.Alg = string(ES256)
	v, err := k.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	if v.Algorithm() != ES256 || v.KeyID() != "e1" {
		t.Fatalf("unexpected verifier: alg=%s kid=%s", v.Algorithm(), v.KeyID())
	}
}

func TestVerifierForAlgAntiConfusion(t *testing.T) {
	tk := newTestKeys(t)
	rsaKey := FromRSAPublicKey(&tk.rsa2048.PublicKey, "r1")
	ecKey := FromECDSAPublicKey(&tk.p256.PublicKey, "e1")
	octKey := FromHMACSecret(tk.hmac, "h1")

	cases := []struct {
		name string
		key  Key
		alg  Algorithm
		want error
	}{
		{"rsa key for HS256", rsaKey, HS256, ErrAlgorithmNotAllowed},
		{"oct key for RS256", octKey, RS256, ErrAlgorithmNotAllowed},
		{"oct key for ES256", octKey, ES256, ErrAlgorithmNotAllowed},
		{"ec key for PS256", ecKey, PS256, ErrAlgorithmNotAllowed},
		{"ec key for EdDSA", ecKey, EdDSA, ErrAlgorithmNotAllowed},
		{"rsa key for unknown alg", rsaKey, Algorithm("XX999"), ErrUnsupportedAlgorithm},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.key.verifierForAlg(c.alg); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestVerifierForAlgHappyPaths(t *testing.T) {
	tk := newTestKeys(t)
	cases := []struct {
		key Key
		alg Algorithm
	}{
		{FromHMACSecret(tk.hmac, "h1"), HS256},
		{FromRSAPublicKey(&tk.rsa2048.PublicKey, "r1"), PS256},
		{FromRSAPublicKey(&tk.rsa2048.PublicKey, "r1"), RS256},
		{FromECDSAPublicKey(&tk.p256.PublicKey, "e1"), ES256},
		{FromEd25519PublicKey(tk.edPub, "o1"), EdDSA},
	}
	for _, c := range cases {
		v, err := c.key.verifierForAlg(c.alg)
		if err != nil {
			t.Fatalf("%s: %v", c.alg, err)
		}
		if v.Algorithm() != c.alg {
			t.Fatalf("%s: verifier alg = %s", c.alg, v.Algorithm())
		}
	}
}
