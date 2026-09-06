package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"math/big"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// KeyType is the RFC 7517 §4.1 "kty" value.
type KeyType string

const (
	KeyTypeRSA KeyType = "RSA"
	KeyTypeEC  KeyType = "EC"
	KeyTypeOKP KeyType = "OKP" // Ed25519 (RFC 8037)
	KeyTypeOct KeyType = "oct" // symmetric; internal use only
)

// Key is a single JSON Web Key (RFC 7517 §4). A Key with Kty == KeyTypeOct
// MUST NOT be serialized into a JWKS document served over HTTP, so
// MarshalJSON returns ErrOctNotServable for it (spec §5.3).
type Key struct {
	Kty KeyType
	Kid string
	Use string // "sig" | "enc"
	Alg string

	// Parsed key material; access it via PublicKey() / Secret().
	n, e []byte // RSA
	crv  string // EC, OKP
	x, y []byte // EC (x, y); OKP (x only)
	k    []byte // oct
}

type jwkJSON struct {
	Kty KeyType `json:"kty"`
	Kid string  `json:"kid,omitempty"`
	Use string  `json:"use,omitempty"`
	Alg string  `json:"alg,omitempty"`
	N   string  `json:"n,omitempty"`
	E   string  `json:"e,omitempty"`
	Crv string  `json:"crv,omitempty"`
	X   string  `json:"x,omitempty"`
	Y   string  `json:"y,omitempty"`
	K   string  `json:"k,omitempty"`
}

// MarshalJSON renders the key as an RFC 7517 JWK object. It returns
// ErrOctNotServable for symmetric keys so a symmetric secret can never be
// published in a discoverable keyset by accident.
func (k Key) MarshalJSON() ([]byte, error) {
	if k.Kty == KeyTypeOct {
		return nil, ErrOctNotServable
	}
	j := jwkJSON{Kty: k.Kty, Kid: k.Kid, Use: k.Use, Alg: k.Alg, Crv: k.crv}
	if len(k.n) > 0 {
		j.N = b64.Encode(k.n)
	}
	if len(k.e) > 0 {
		j.E = b64.Encode(k.e)
	}
	if len(k.x) > 0 {
		j.X = b64.Encode(k.x)
	}
	if len(k.y) > 0 {
		j.Y = b64.Encode(k.y)
	}
	return json.Marshal(j)
}

// UnmarshalJSON parses an RFC 7517 JWK object.
func (k *Key) UnmarshalJSON(b []byte) error {
	var j jwkJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	k.Kty, k.Kid, k.Use, k.Alg, k.crv = j.Kty, j.Kid, j.Use, j.Alg, j.Crv
	dec := func(s string) ([]byte, error) {
		if s == "" {
			return nil, nil
		}
		return b64.Decode(s)
	}
	var err error
	if k.n, err = dec(j.N); err != nil {
		return err
	}
	if k.e, err = dec(j.E); err != nil {
		return err
	}
	if k.x, err = dec(j.X); err != nil {
		return err
	}
	if k.y, err = dec(j.Y); err != nil {
		return err
	}
	if k.k, err = dec(j.K); err != nil {
		return err
	}
	return nil
}

// FromRSAPublicKey builds a "sig" JWK from an RSA public key.
func FromRSAPublicKey(pub *rsa.PublicKey, kid string) Key {
	return Key{
		Kty: KeyTypeRSA,
		Kid: kid,
		n:   pub.N.Bytes(),
		e:   big.NewInt(int64(pub.E)).Bytes(),
	}
}

// FromECDSAPublicKey builds a "sig" JWK from an ECDSA public key.
func FromECDSAPublicKey(pub *ecdsa.PublicKey, kid string) Key {
	size := (pub.Curve.Params().BitSize + 7) / 8
	return Key{
		Kty: KeyTypeEC,
		Kid: kid,
		crv: curveName(pub.Curve),
		x:   leftPad(pub.X.Bytes(), size),
		y:   leftPad(pub.Y.Bytes(), size),
	}
}

// FromEd25519PublicKey builds a "sig" JWK from an Ed25519 public key.
func FromEd25519PublicKey(pub ed25519.PublicKey, kid string) Key {
	return Key{
		Kty: KeyTypeOKP,
		Kid: kid,
		crv: "Ed25519",
		x:   append([]byte(nil), pub...),
	}
}

// FromHMACSecret builds a symmetric (kty "oct") JWK. Such a key cannot be
// marshaled into a servable JWKS document (see MarshalJSON).
func FromHMACSecret(secret []byte, kid string) Key {
	return Key{
		Kty: KeyTypeOct,
		Kid: kid,
		k:   append([]byte(nil), secret...),
	}
}

// PublicKey reconstructs the stdlib public key for an RSA/EC/OKP JWK.
func (k Key) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case KeyTypeRSA:
		if len(k.n) == 0 || len(k.e) == 0 {
			return nil, ErrMalformedKey
		}
		e := new(big.Int).SetBytes(k.e)
		if e.BitLen() == 0 || e.BitLen() > 32 {
			return nil, ErrMalformedKey
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(k.n), E: int(e.Int64())}, nil
	case KeyTypeEC:
		c := curveByName(k.crv)
		if c == nil || len(k.x) == 0 || len(k.y) == 0 {
			return nil, ErrMalformedKey
		}
		return &ecdsa.PublicKey{
			Curve: c,
			X:     new(big.Int).SetBytes(k.x),
			Y:     new(big.Int).SetBytes(k.y),
		}, nil
	case KeyTypeOKP:
		if k.crv != "Ed25519" || len(k.x) != ed25519.PublicKeySize {
			return nil, ErrMalformedKey
		}
		return ed25519.PublicKey(append([]byte(nil), k.x...)), nil
	default:
		return nil, ErrMalformedKey
	}
}

// Secret returns the raw symmetric key bytes for an "oct" JWK.
func (k Key) Secret() ([]byte, error) {
	if k.Kty != KeyTypeOct {
		return nil, ErrKeyTypeMismatch
	}
	if len(k.k) == 0 {
		return nil, ErrMalformedKey
	}
	return append([]byte(nil), k.k...), nil
}

// Verifier builds a Verifier from the key material and the key's own Alg.
func (k Key) Verifier() (Verifier, error) {
	return k.verifierForAlg(Algorithm(k.Alg))
}

// verifierForAlg builds a Verifier for alg, enforcing the anti-confusion
// rule that the key's type must match the algorithm family (spec §4.10).
func (k Key) verifierForAlg(alg Algorithm) (Verifier, error) {
	switch family(alg) {
	case familyHMAC:
		secret, err := k.Secret()
		if err != nil {
			return nil, ErrAlgorithmNotAllowed
		}
		return NewHMACVerifier(alg, secret, k.Kid)
	case familyRSAPSS:
		pub, err := k.rsaPublic()
		if err != nil {
			return nil, err
		}
		return NewRSAPSSVerifier(alg, pub, k.Kid)
	case familyRSAPKCS1:
		pub, err := k.rsaPublic()
		if err != nil {
			return nil, err
		}
		return NewRSAPKCS1Verifier(alg, pub, k.Kid)
	case familyECDSA:
		if k.Kty != KeyTypeEC {
			return nil, ErrAlgorithmNotAllowed
		}
		pub, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		return NewECDSAVerifier(alg, pub.(*ecdsa.PublicKey), k.Kid)
	case familyEdDSA:
		if k.Kty != KeyTypeOKP {
			return nil, ErrAlgorithmNotAllowed
		}
		pub, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		return NewEd25519Verifier(pub.(ed25519.PublicKey), k.Kid)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func (k Key) rsaPublic() (*rsa.PublicKey, error) {
	if k.Kty != KeyTypeRSA {
		return nil, ErrAlgorithmNotAllowed
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return ""
	}
}

func curveByName(s string) elliptic.Curve {
	switch s {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
