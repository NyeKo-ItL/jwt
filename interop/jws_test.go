package interop

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	jwt "github.com/NyeKo-ItL/jwt"
	jose "github.com/go-jose/go-jose/v4"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// jwsAlgs is the full JWS matrix. ourSign is false for the PKCS#1 v1.5
// family, which this library verifies but never produces (spec §0.2).
var jwsAlgs = []struct {
	alg     jwt.Algorithm
	ourSign bool
}{
	{jwt.HS256, true}, {jwt.HS384, true}, {jwt.HS512, true},
	{jwt.RS256, false}, {jwt.RS384, false}, {jwt.RS512, false},
	{jwt.PS256, true}, {jwt.PS384, true}, {jwt.PS512, true},
	{jwt.ES256, true}, {jwt.ES384, true}, {jwt.ES512, true},
	{jwt.EdDSA, true},
}

const marker = "interop-marker"

type payload struct {
	jwt.RegisteredClaims
	Marker string `json:"marker"`
}

func wantPayloadJSON(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"sub":    "interop",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"marker": marker,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertPayload(t *testing.T, raw []byte) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if m["sub"] != "interop" || m["marker"] != marker {
		t.Fatalf("payload mismatch: %s", raw)
	}
}

// ---- this library ----

func oursSign(t *testing.T, alg jwt.Algorithm) string {
	t.Helper()
	var (
		s   jwt.Signer
		err error
	)
	switch alg {
	case jwt.HS256, jwt.HS384, jwt.HS512:
		s, err = jwt.NewHMACSigner(alg, keys.hmac, "k")
	case jwt.PS256, jwt.PS384, jwt.PS512:
		s, err = jwt.NewRSAPSSSigner(alg, keys.rsa, "k")
	case jwt.ES256:
		s, err = jwt.NewECDSASigner(alg, keys.p256, "k")
	case jwt.ES384:
		s, err = jwt.NewECDSASigner(alg, keys.p384, "k")
	case jwt.ES512:
		s, err = jwt.NewECDSASigner(alg, keys.p521, "k")
	case jwt.EdDSA:
		s, err = jwt.NewEd25519Signer(keys.edPriv, "k")
	default:
		t.Fatalf("no built-in signer for %s", alg)
	}
	if err != nil {
		t.Fatalf("new signer %s: %v", alg, err)
	}
	tok, err := jwt.Sign(payload{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "interop",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Marker: marker,
	}, s)
	if err != nil {
		t.Fatalf("Sign %s: %v", alg, err)
	}
	return tok
}

func oursKeyProvider(t *testing.T, alg jwt.Algorithm) jwt.KeyProvider {
	t.Helper()
	switch alg {
	case jwt.HS256, jwt.HS384, jwt.HS512:
		return jwt.StaticKeyProvider(jwt.FromHMACSecret(keys.hmac, "k"))
	case jwt.RS256, jwt.RS384, jwt.RS512, jwt.PS256, jwt.PS384, jwt.PS512:
		return jwt.StaticKeyProvider(jwt.FromRSAPublicKey(&keys.rsa.PublicKey, "k"))
	case jwt.ES256:
		return jwt.StaticKeyProvider(jwt.FromECDSAPublicKey(&keys.p256.PublicKey, "k"))
	case jwt.ES384:
		return jwt.StaticKeyProvider(jwt.FromECDSAPublicKey(&keys.p384.PublicKey, "k"))
	case jwt.ES512:
		return jwt.StaticKeyProvider(jwt.FromECDSAPublicKey(&keys.p521.PublicKey, "k"))
	case jwt.EdDSA:
		return jwt.StaticKeyProvider(jwt.FromEd25519PublicKey(keys.edPub, "k"))
	default:
		t.Fatalf("no key provider for %s", alg)
		return nil
	}
}

func oursParse(t *testing.T, alg jwt.Algorithm, token string) {
	t.Helper()
	c, err := jwt.Parse[payload](context.Background(), token, oursKeyProvider(t, alg),
		jwt.WithAllowedAlgorithms(alg))
	if err != nil {
		t.Fatalf("jwt.Parse %s: %v", alg, err)
	}
	if c.Subject != "interop" || c.Marker != marker {
		t.Fatalf("parsed claims mismatch: %+v", c)
	}
}

// ---- go-jose/v4 ----

func joseSigAlg(alg jwt.Algorithm) jose.SignatureAlgorithm {
	return jose.SignatureAlgorithm(string(alg))
}

func josePriv(alg jwt.Algorithm) any {
	switch alg {
	case jwt.HS256, jwt.HS384, jwt.HS512:
		return keys.hmac
	case jwt.RS256, jwt.RS384, jwt.RS512, jwt.PS256, jwt.PS384, jwt.PS512:
		return keys.rsa
	case jwt.ES256:
		return keys.p256
	case jwt.ES384:
		return keys.p384
	case jwt.ES512:
		return keys.p521
	case jwt.EdDSA:
		return keys.edPriv
	}
	return nil
}

func josePub(alg jwt.Algorithm) any {
	switch alg {
	case jwt.HS256, jwt.HS384, jwt.HS512:
		return keys.hmac
	case jwt.RS256, jwt.RS384, jwt.RS512, jwt.PS256, jwt.PS384, jwt.PS512:
		return &keys.rsa.PublicKey
	case jwt.ES256:
		return &keys.p256.PublicKey
	case jwt.ES384:
		return &keys.p384.PublicKey
	case jwt.ES512:
		return &keys.p521.PublicKey
	case jwt.EdDSA:
		return keys.edPub
	}
	return nil
}

func joseSign(t *testing.T, alg jwt.Algorithm) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: joseSigAlg(alg), Key: josePriv(alg)}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner %s: %v", alg, err)
	}
	obj, err := signer.Sign(wantPayloadJSON(t))
	if err != nil {
		t.Fatalf("jose sign %s: %v", alg, err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func joseVerify(t *testing.T, alg jwt.Algorithm, token string) {
	t.Helper()
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{joseSigAlg(alg)})
	if err != nil {
		t.Fatalf("jose.ParseSigned %s: %v", alg, err)
	}
	raw, err := jws.Verify(josePub(alg))
	if err != nil {
		t.Fatalf("jose verify %s: %v", alg, err)
	}
	assertPayload(t, raw)
}

// ---- golang-jwt/v5 ----

func ghSign(t *testing.T, alg jwt.Algorithm) string {
	t.Helper()
	method := jwtv5.GetSigningMethod(string(alg))
	if method == nil {
		t.Fatalf("golang-jwt has no method %s", alg)
	}
	tok := jwtv5.NewWithClaims(method, jwtv5.MapClaims{
		"sub":    "interop",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"marker": marker,
	})
	var key any
	switch alg {
	case jwt.HS256, jwt.HS384, jwt.HS512:
		key = keys.hmac
	case jwt.RS256, jwt.RS384, jwt.RS512, jwt.PS256, jwt.PS384, jwt.PS512:
		key = keys.rsa
	case jwt.ES256:
		key = keys.p256
	case jwt.ES384:
		key = keys.p384
	case jwt.ES512:
		key = keys.p521
	case jwt.EdDSA:
		key = keys.edPriv
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("golang-jwt sign %s: %v", alg, err)
	}
	return s
}

func ghVerify(t *testing.T, alg jwt.Algorithm, token string) {
	t.Helper()
	parsed, err := jwtv5.Parse(token, func(*jwtv5.Token) (any, error) {
		return josePub(alg), nil
	}, jwtv5.WithValidMethods([]string{string(alg)}))
	if err != nil {
		t.Fatalf("golang-jwt parse %s: %v", alg, err)
	}
	claims := parsed.Claims.(jwtv5.MapClaims)
	if claims["sub"] != "interop" || claims["marker"] != marker {
		t.Fatalf("golang-jwt claims mismatch: %v", claims)
	}
}

// ---- the matrix ----

func TestJWS_OursVerifiedElsewhere(t *testing.T) {
	for _, c := range jwsAlgs {
		if !c.ourSign {
			continue
		}
		t.Run(string(c.alg), func(t *testing.T) {
			tok := oursSign(t, c.alg)
			joseVerify(t, c.alg, tok)
			ghVerify(t, c.alg, tok)
		})
	}
}

func TestJWS_ElsewhereVerifiedByOurs(t *testing.T) {
	for _, c := range jwsAlgs {
		t.Run(string(c.alg)+"/from-go-jose", func(t *testing.T) {
			oursParse(t, c.alg, joseSign(t, c.alg))
		})
		t.Run(string(c.alg)+"/from-golang-jwt", func(t *testing.T) {
			oursParse(t, c.alg, ghSign(t, c.alg))
		})
	}
}
