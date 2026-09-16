package jwt

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// RFC 9864 (Fully-Specified Algorithms for JOSE and COSE) registers "Ed25519"
// and deprecates the polymorphic "EdDSA" (§2.2, §4.1.2). Key representation
// is unchanged apart from the "alg" value (§5).

// RFC 8037 Appendix A.1 / A.4 key and signature.
const (
	rfc8037D   = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037X   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037JWS = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func rfc8037Key(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()

	priv := ed25519.NewKeyFromSeed(mustB64(t, rfc8037D))

	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || b64.Encode(pub) != rfc8037X {
		t.Fatal("RFC 8037 A.1: d does not derive the published x")
	}

	return priv, pub
}

func TestEd25519AlgorithmIdentifier(t *testing.T) {
	if Ed25519 != "Ed25519" {
		t.Fatalf("Ed25519 = %q", Ed25519)
	}

	if EdDSA != "EdDSA" {
		t.Fatalf("EdDSA = %q", EdDSA)
	}
}

func TestEd25519SignerEmitsFullySpecifiedAlg(t *testing.T) {
	priv, pub := rfc8037Key(t)

	s, err := NewEd25519Signer(priv, "o1")
	if err != nil {
		t.Fatal(err)
	}

	v, _ := NewEd25519Verifier(pub, "o1")
	if s.Algorithm() != Ed25519 || v.Algorithm() != Ed25519 {
		t.Fatalf("signer/verifier algorithm = %q/%q, want Ed25519", s.Algorithm(), v.Algorithm())
	}

	tok, err := Sign(appClaims{}, s)
	if err != nil {
		t.Fatal(err)
	}

	var hdr Header

	h, _, _, _ := split3(tok)
	if err := json.Unmarshal(mustB64(t, h), &hdr); err != nil || hdr.Algorithm != "Ed25519" {
		t.Fatalf("header alg = %q (%v), want Ed25519", hdr.Algorithm, err)
	}
}

func TestEd25519SignatureMatchesRFC8037Vector(t *testing.T) {
	// Ed25519 is deterministic: the built-in signer must reproduce the
	// RFC 8037 A.4 signature bytes for the same signing input.
	priv, _ := rfc8037Key(t)
	s, _ := NewEd25519Signer(priv)
	h, p, want, _ := split3(rfc8037JWS)

	sig, err := s.Sign([]byte(h + "." + p))
	if err != nil || b64.Encode(sig) != want {
		t.Fatalf("signature = %s (%v)\nwant        %s", b64.Encode(sig), err, want)
	}
}

func TestParseEd25519AllowlistIsExplicit(t *testing.T) {
	priv, pub := rfc8037Key(t)
	keys := StaticKeyProvider(FromEd25519PublicKey(pub))

	s, _ := NewEd25519Signer(priv)
	modern, _ := Sign(appClaims{}, s)

	// RFC 8037 A.4 is a legacy "EdDSA" JWS whose payload is not a JSON
	// object; re-sign a claims payload under the legacy header instead.
	legacy := signRawEd25519(priv, `{"alg":"EdDSA"}`, `{}`)

	cases := []struct {
		name    string
		tok     string
		allowed []Algorithm
		ok      bool
	}{
		{"Ed25519 token, Ed25519 allowed", modern, []Algorithm{Ed25519}, true},
		{"Ed25519 token, only EdDSA allowed", modern, []Algorithm{EdDSA}, false},
		{"legacy EdDSA token, EdDSA allowed", legacy, []Algorithm{EdDSA}, true},
		{"legacy EdDSA token, only Ed25519 allowed", legacy, []Algorithm{Ed25519}, false},
		{"both allowed", legacy, []Algorithm{Ed25519, EdDSA}, true},
		{"case differs", modern, []Algorithm{"ED25519"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse[appClaims](ctx(), tc.tok, keys, WithAllowedAlgorithms(tc.allowed...))
			if tc.ok && err != nil {
				t.Fatalf("err = %v", err)
			}

			if !tc.ok && !errors.Is(err, ErrAlgorithmNotAllowed) {
				t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
			}
		})
	}
}

func TestParseRFC8037LegacyVectorVerifies(t *testing.T) {
	_, pub := rfc8037Key(t)
	h, p, s, _ := split3(rfc8037JWS)

	v, _ := StaticKeyProvider(FromEd25519PublicKey(pub)).(staticKeyProvider).key.verifierForAlg(EdDSA)
	if err := v.Verify([]byte(h+"."+p), mustB64(t, s)); err != nil {
		t.Fatalf("RFC 8037 A.4 signature does not verify: %v", err)
	}

	if v.Algorithm() != EdDSA {
		t.Fatalf("verifier built for EdDSA reports %q", v.Algorithm())
	}
}

func TestJWKAlgEdDSAAndEd25519AreTheSameKey(t *testing.T) {
	// §5: the key representation only differs in "alg", so a JWK published
	// with either value serves both identifiers — while still refusing any
	// other algorithm (RFC 8725 §3.1).
	priv, pub := rfc8037Key(t)
	s, _ := NewEd25519Signer(priv)
	modern, _ := Sign(appClaims{}, s)
	legacy := signRawEd25519(priv, `{"alg":"EdDSA"}`, `{}`)

	for _, keyAlg := range []string{"Ed25519", "EdDSA"} {
		k := FromEd25519PublicKey(pub)
		k.Alg = keyAlg

		for _, tok := range []string{modern, legacy} {
			if _, err := parse[appClaims](ctx(), tok, StaticKeyProvider(k), WithAllowedAlgorithms(Ed25519, EdDSA)); err != nil {
				t.Errorf("key alg %s: %v", keyAlg, err)
			}
		}

		if _, err := k.Verifier(); err != nil {
			t.Errorf("Key.Verifier with alg %s: %v", keyAlg, err)
		}
	}

	ecKey := FromECDSAPublicKey(&newTestKeys(t).p256.PublicKey)
	ecKey.Alg = "Ed25519"

	if _, err := ecKey.verifierForAlg(Ed25519); err == nil {
		t.Fatal("an EC key satisfied an Ed25519 header")
	}

	edKey := FromEd25519PublicKey(pub)
	edKey.Alg = "Ed25519"

	if err := edKey.permitsVerify(ES256); !errors.Is(err, ErrKeyUsage) {
		t.Fatalf("Ed25519 key permitted ES256: %v", err)
	}
}

func TestEd25519RequiresEd25519Curve(t *testing.T) {
	_, pub := rfc8037Key(t)

	raw := []byte(`{"kty":"OKP","crv":"Ed448","x":"` + b64.Encode(pub) + `"}`)

	k, err := ParseKey(raw)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := k.verifierForAlg(Ed25519); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("Ed448-labelled key used for Ed25519: %v", err)
	}
}

func signRawEd25519(priv ed25519.PrivateKey, headerJSON, payloadJSON string) string {
	input := b64.Encode([]byte(headerJSON)) + "." + b64.Encode([]byte(payloadJSON))

	return input + "." + b64.Encode(ed25519.Sign(priv, []byte(input)))
}
