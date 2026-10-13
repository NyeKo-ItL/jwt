package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

var v1CoreSecret = []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

type v1CoreClaims struct {
	RegisteredClaims
	Value int `json:"value"`
}

type v1CorePartialClaims struct {
	First int `json:"first"`
	Last  int `json:"last"`
}

func v1CoreSigner(t *testing.T, alg Algorithm, kid string) Signer {
	t.Helper()

	signer, err := NewHMACSigner(alg, v1CoreSecret, kid)
	if err != nil {
		t.Fatal(err)
	}

	return signer
}

func v1CoreKeys(alg Algorithm, kid string) KeyProvider {
	key := FromHMACSecret(v1CoreSecret, kid)
	key.Alg = string(alg)

	return StaticKeyProvider(key)
}

func v1CoreRawToken(t *testing.T, payload string, alg Algorithm, kid string) string {
	t.Helper()

	header, err := json.Marshal(Header{Algorithm: alg, KeyID: kid})
	if err != nil {
		t.Fatal(err)
	}

	signingInput := b64.Encode(header) + "." + b64.Encode([]byte(payload))

	sig, err := v1CoreSigner(t, alg, kid).Sign([]byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}

	return signingInput + "." + b64.Encode(sig)
}

func TestV1CoreAtomicDestinations(t *testing.T) {
	token := v1CoreRawToken(t, `{"first":2,"last":"bad"}`, HS256, "k1")
	keys := v1CoreKeys(HS256, "k1")

	t.Run("Parse struct", func(t *testing.T) {
		dst := v1CorePartialClaims{First: 10, Last: 20}

		err := Parse(context.Background(), token, &dst, keys, WithAllowedAlgorithms(HS256))
		if !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("error = %v", err)
		}

		if dst != (v1CorePartialClaims{First: 10, Last: 20}) {
			t.Fatalf("destination changed: %+v", dst)
		}
	})

	t.Run("Parse map", func(t *testing.T) {
		dst := map[string]int{"original": 1}

		err := Parse(context.Background(), token, &dst, keys, WithAllowedAlgorithms(HS256))
		if !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("error = %v", err)
		}

		if len(dst) != 1 || dst["original"] != 1 {
			t.Fatalf("destination changed: %#v", dst)
		}
	})

	t.Run("ParseInsecure", func(t *testing.T) {
		dst := v1CorePartialClaims{First: 10, Last: 20}

		err := ParseInsecure(token, &dst)
		if !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("error = %v", err)
		}

		if dst != (v1CorePartialClaims{First: 10, Last: 20}) {
			t.Fatalf("destination changed: %+v", dst)
		}
	})

	t.Run("ClaimsFromContext", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), claimsContextKey{}, []byte(`{"first":2,"last":"bad"}`))
		dst := v1CorePartialClaims{First: 10, Last: 20}

		err := ClaimsFromContext(ctx, &dst)
		if !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("error = %v", err)
		}

		if dst != (v1CorePartialClaims{First: 10, Last: 20}) {
			t.Fatalf("destination changed: %+v", dst)
		}
	})

	if err := Parse(context.Background(), token, (*v1CoreClaims)(nil), keys, WithAllowedAlgorithms(HS256)); !errors.Is(err, ErrInvalidDestination) {
		t.Fatalf("Parse nil destination = %v", err)
	}

	if err := ParseInsecure(token, (*v1CoreClaims)(nil)); !errors.Is(err, ErrInvalidDestination) {
		t.Fatalf("ParseInsecure nil destination = %v", err)
	}

	if err := ClaimsFromContext(context.Background(), (*v1CoreClaims)(nil)); !errors.Is(err, ErrInvalidDestination) {
		t.Fatalf("ClaimsFromContext nil destination = %v", err)
	}
}

func TestV1CoreNilOptionsAndObjectClaims(t *testing.T) {
	signer := v1CoreSigner(t, HS256, "k1")

	var (
		signOption      SignOption
		typedSignOption *SignOptions
	)

	token, err := Sign(v1CoreClaims{Value: 7}, signer, signOption, typedSignOption)
	if err != nil {
		t.Fatalf("Sign with nil options: %v", err)
	}

	var (
		parseOption      ParseOption
		typedParseOption *ParseOptions
		got              v1CoreClaims
	)
	if err := Parse(context.Background(), token, &got, v1CoreKeys(HS256, "k1"), parseOption, typedParseOption, WithAllowedAlgorithms(HS256)); err != nil {
		t.Fatalf("Parse with nil options: %v", err)
	}

	if got.Value != 7 {
		t.Fatalf("claims = %+v", got)
	}

	for name, claims := range map[string]any{
		"null":   nil,
		"string": "claims",
		"array":  []int{1},
		"number": 1,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(claims, signer); !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestV1CoreRequiredClaimRejectsNull(t *testing.T) {
	token := v1CoreRawToken(t, `{"required":null,"zero":0,"false":false}`, HS256, "k1")
	keys := v1CoreKeys(HS256, "k1")

	var dst map[string]any
	if err := Parse(context.Background(), token, &dst, keys, WithAllowedAlgorithms(HS256), WithRequiredClaims("required")); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("null required claim = %v", err)
	}

	if err := Parse(context.Background(), token, &dst, keys, WithAllowedAlgorithms(HS256), WithRequiredClaims("zero", "false")); err != nil {
		t.Fatalf("non-null falsey claims rejected: %v", err)
	}
}

func TestV1CoreParseInsecureRequiresThreeSegments(t *testing.T) {
	payload := b64.Encode([]byte(`{"value":1}`))
	for _, token := range []string{"header." + payload, "header." + payload + ".sig.extra"} {
		var dst v1CoreClaims
		if err := ParseInsecure(token, &dst); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("ParseInsecure(%q) = %v", token, err)
		}
	}
}

type v1CoreCountingProvider struct {
	calls int
	key   Key
	err   error
}

func (p *v1CoreCountingProvider) Lookup(context.Context, string) (Key, bool, error) {
	p.calls++
	if p.err != nil {
		return Key{}, false, p.err
	}

	return p.key, true, nil
}

func TestV1CoreCanonicalSegmentsCheckedBeforeProvider(t *testing.T) {
	header := b64.Encode([]byte(`{"alg":"HS256","kid":"k1"}`))
	payload := b64.Encode([]byte(`{}`))
	provider := &v1CoreCountingProvider{key: FromHMACSecret(v1CoreSecret, "k1")}

	for name, token := range map[string]string{
		"payload padding":   header + "." + payload + "=.AA",
		"signature padding": header + "." + payload + ".AA=",
	} {
		t.Run(name, func(t *testing.T) {
			provider.calls = 0

			var dst v1CoreClaims

			err := Parse(context.Background(), token, &dst, provider, WithAllowedAlgorithms(HS256))
			if !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("error = %v", err)
			}

			if provider.calls != 0 {
				t.Fatalf("provider called %d times", provider.calls)
			}
		})
	}
}

type v1CoreVerifierProvider struct {
	verifier Verifier
	err      error
	calls    int
}

func (p *v1CoreVerifierProvider) LookupVerifier(context.Context, Algorithm, string) (Verifier, bool, error) {
	p.calls++
	if p.err != nil {
		return nil, false, p.err
	}

	return p.verifier, p.verifier != nil, nil
}

type v1CoreFailingVerifier struct {
	alg Algorithm
	kid string
	err error
}

func (v v1CoreFailingVerifier) Algorithm() Algorithm        { return v.alg }
func (v v1CoreFailingVerifier) KeyID() string               { return v.kid }
func (v v1CoreFailingVerifier) Verify([]byte, []byte) error { return v.err }

func TestV1CoreVerifierProvider(t *testing.T) {
	token, err := Sign(v1CoreClaims{Value: 9}, v1CoreSigner(t, HS256, "k1"))
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewHMACVerifier(HS256, v1CoreSecret, "k1")
	if err != nil {
		t.Fatal(err)
	}

	provider := &v1CoreVerifierProvider{verifier: verifier}

	var got v1CoreClaims
	if err := Parse(context.Background(), token, &got, nil, WithAllowedAlgorithms(HS256), WithVerifierProvider(provider)); err != nil {
		t.Fatalf("custom provider Parse: %v", err)
	}

	if got.Value != 9 || provider.calls != 1 {
		t.Fatalf("claims/provider = %+v/%d", got, provider.calls)
	}

	provider.calls = 0
	if err := Parse(context.Background(), token, &got, nil, WithAllowedAlgorithms(HS384), WithVerifierProvider(provider)); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("allowlist error = %v", err)
	}

	if provider.calls != 0 {
		t.Fatalf("provider called before allowlist check")
	}

	t.Run("algorithm control", func(t *testing.T) {
		wrong, _ := NewHMACVerifier(HS384, v1CoreSecret, "k1")

		p := &v1CoreVerifierProvider{verifier: wrong}
		if err := Parse(context.Background(), token, &got, nil, WithAllowedAlgorithms(HS256), WithVerifierProvider(p)); !errors.Is(err, ErrKeyUsage) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("kid control", func(t *testing.T) {
		wrong, _ := NewHMACVerifier(HS256, v1CoreSecret, "other")

		p := &v1CoreVerifierProvider{verifier: wrong}
		if err := Parse(context.Background(), token, &got, nil, WithAllowedAlgorithms(HS256), WithVerifierProvider(p)); !errors.Is(err, ErrKeyUsage) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("provider error identity", func(t *testing.T) {
		original := errors.New("provider failed")
		p := &v1CoreVerifierProvider{err: original}

		err := Parse(context.Background(), token, &got, nil, WithAllowedAlgorithms(HS256), WithVerifierProvider(p))
		if !errors.Is(err, ErrVerifierProvider) || !errors.Is(err, original) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("verifier error identity", func(t *testing.T) {
		original := errors.New("verifier failed")
		p := &v1CoreVerifierProvider{verifier: v1CoreFailingVerifier{alg: HS256, kid: "k1", err: original}}

		err := Parse(context.Background(), token, &got, nil, WithAllowedAlgorithms(HS256), WithVerifierProvider(p))
		if !errors.Is(err, ErrInvalidSignature) || !errors.Is(err, original) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestV1CoreKeyProviderErrorAndOneKeyOneAlgorithm(t *testing.T) {
	token, err := Sign(v1CoreClaims{}, v1CoreSigner(t, HS256, "k1"))
	if err != nil {
		t.Fatal(err)
	}

	original := errors.New("key backend failed")
	badProvider := &v1CoreCountingProvider{err: original}

	var dst v1CoreClaims

	err = Parse(context.Background(), token, &dst, badProvider, WithAllowedAlgorithms(HS256))
	if !errors.Is(err, ErrKeyProvider) || !errors.Is(err, original) {
		t.Fatalf("provider error = %v", err)
	}

	ambiguous := FromHMACSecret(v1CoreSecret, "k1")

	err = Parse(context.Background(), token, &dst, StaticKeyProvider(ambiguous), WithAllowedAlgorithms(HS256, HS384))
	if !errors.Is(err, ErrKeyUsage) {
		t.Fatalf("ambiguous key error = %v", err)
	}

	if err := Parse(context.Background(), token, &dst, StaticKeyProvider(ambiguous), WithAllowedAlgorithms(HS256)); err != nil {
		t.Fatalf("single-alg allowlist rejected: %v", err)
	}

	ambiguous.Alg = string(HS256)
	if err := Parse(context.Background(), token, &dst, StaticKeyProvider(ambiguous), WithAllowedAlgorithms(HS256, HS384)); err != nil {
		t.Fatalf("alg-bound key rejected: %v", err)
	}
}

func TestV1CoreRawHelperUsesCorrectMAC(t *testing.T) {
	// Guard the local fixture helper against accidentally creating tokens that
	// pass only because a verifier callback ignores the signature.
	token := v1CoreRawToken(t, `{}`, HS256, "k1")

	h, p, s, ok := split3(token)
	if !ok {
		t.Fatal("invalid fixture token")
	}

	sig, err := b64.Decode(s)
	if err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, v1CoreSecret)

	_, _ = mac.Write([]byte(h + "." + p))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		t.Fatal("fixture signature mismatch")
	}
}
