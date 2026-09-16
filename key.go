package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"

	internalalg "github.com/NyeKo-ItL/jwt/internal/alg"
	"github.com/NyeKo-ItL/jwt/internal/b64"
	internalkeyparse "github.com/NyeKo-ItL/jwt/internal/keyparse"
	"github.com/NyeKo-ItL/jwt/internal/option"
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
	// Use is the RFC 7517 §4.2 public key use: "sig" or "enc". When set to
	// anything other than "sig", the key cannot verify signatures.
	Use string
	// KeyOps is the RFC 7517 §4.3 list of permitted operations. When
	// non-empty, it must contain "verify" for the key to verify signatures.
	KeyOps []string
	// Alg is the RFC 7517 §4.4 algorithm the key is intended for. When set,
	// the key only verifies tokens whose header "alg" is identical
	// (RFC 8725 §3.1: one key, one algorithm).
	Alg string

	// Parsed key material; access it via PublicKey() / Secret().
	n, e []byte // RSA
	crv  string // EC, OKP
	x, y []byte // EC (x, y); OKP (x only)
	k    []byte // oct
}

type jwkJSON struct {
	Kty    KeyType  `json:"kty"`
	Kid    string   `json:"kid,omitempty"`
	Use    string   `json:"use,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
	K      string   `json:"k,omitempty"`
}

// MarshalJSON renders the key as an RFC 7517 JWK object. It returns
// ErrOctNotServable for symmetric keys so a symmetric secret can never be
// published in a discoverable keyset by accident.
func (k Key) MarshalJSON() ([]byte, error) {
	if k.Kty == KeyTypeOct {
		return nil, ErrOctNotServable
	}

	j := jwkJSON{Kty: k.Kty, Kid: k.Kid, Use: k.Use, KeyOps: k.KeyOps, Alg: k.Alg, Crv: k.crv}
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

// UnmarshalJSON parses an RFC 7517 JWK object. Beyond JSON and base64url
// validity it rejects, with an error wrapping ErrMalformedKey, the encodings
// that would give one key several representations (and thus several RFC 7638
// thumbprints): RSA "n"/"e" with leading zero octets (RFC 7518 §6.3.1.1), EC
// coordinates that are not exactly the curve's coordinate size
// (RFC 7518 §6.2.1.2), and Ed25519 "x" that is not 32 bytes (RFC 8037 §2).
// It also rejects duplicate "key_ops" values and a "key_ops" inconsistent
// with "use" (RFC 7517 §4.3).
func (k *Key) UnmarshalJSON(b []byte) error {
	var j jwkJSON
	if err := decodeObject(b, &j); err != nil {
		return err
	}

	k.Kty, k.Kid, k.Use, k.KeyOps, k.Alg, k.crv = j.Kty, j.Kid, j.Use, j.KeyOps, j.Alg, j.Crv
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

	return k.checkCanonical()
}

// sigKeyOps and encKeyOps are the RFC 7517 §4.3 operations consistent with
// "use":"sig" and "use":"enc" respectively.
var (
	sigKeyOps = map[string]bool{"sign": true, "verify": true}
	encKeyOps = map[string]bool{"encrypt": true, "decrypt": true, "wrapKey": true, "unwrapKey": true, "deriveKey": true, "deriveBits": true}
)

// checkCanonical enforces the single-representation rules documented on
// UnmarshalJSON.
func (k *Key) checkCanonical() error {
	seen := make(map[string]bool, len(k.KeyOps))
	for _, op := range k.KeyOps {
		if seen[op] {
			return fmt.Errorf("%w: duplicate key_ops value %q", ErrMalformedKey, op)
		}

		seen[op] = true

		if (k.Use == "sig" && !sigKeyOps[op]) || (k.Use == "enc" && !encKeyOps[op]) {
			return fmt.Errorf("%w: key_ops %q is inconsistent with use %q", ErrMalformedKey, op, k.Use)
		}
	}

	switch k.Kty {
	case KeyTypeRSA:
		if (len(k.n) > 0 && k.n[0] == 0) || (len(k.e) > 0 && k.e[0] == 0) {
			return fmt.Errorf("%w: RSA n/e must not have leading zero octets", ErrMalformedKey)
		}
	case KeyTypeEC:
		if c := curveByName(k.crv); c != nil {
			size := (c.Params().BitSize + 7) / 8
			if (len(k.x) > 0 && len(k.x) != size) || (len(k.y) > 0 && len(k.y) != size) {
				return fmt.Errorf("%w: %s coordinates must be exactly %d bytes", ErrMalformedKey, k.crv, size)
			}
		}
	case KeyTypeOKP:
		if k.crv == "Ed25519" && len(k.x) > 0 && len(k.x) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: Ed25519 x must be %d bytes", ErrMalformedKey, ed25519.PublicKeySize)
		}
	}

	return nil
}

// FromRSAPublicKey builds a "sig" JWK from an RSA public key.
func FromRSAPublicKey(pub *rsa.PublicKey, kid ...string) Key {
	return Key{
		Kty: KeyTypeRSA,
		Kid: option.FirstString(kid),
		n:   pub.N.Bytes(),
		e:   big.NewInt(int64(pub.E)).Bytes(),
	}
}

// FromECDSAPublicKey builds a "sig" JWK from an ECDSA public key. If the
// point is invalid the coordinate fields are left empty and the failure
// surfaces later, at PublicKey/Verifier time.
func FromECDSAPublicKey(pub *ecdsa.PublicKey, kid ...string) Key {
	k := Key{Kty: KeyTypeEC, Kid: option.FirstString(kid), crv: curveName(pub.Curve)}

	size := (pub.Curve.Params().BitSize + 7) / 8
	if b, err := pub.Bytes(); err == nil && len(b) == 1+2*size {
		k.x = append([]byte(nil), b[1:1+size]...)
		k.y = append([]byte(nil), b[1+size:]...)
	}

	return k
}

// FromEd25519PublicKey builds a "sig" JWK from an Ed25519 public key.
func FromEd25519PublicKey(pub ed25519.PublicKey, kid ...string) Key {
	return Key{
		Kty: KeyTypeOKP,
		Kid: option.FirstString(kid),
		crv: "Ed25519",
		x:   append([]byte(nil), pub...),
	}
}

// FromHMACSecret builds a symmetric (kty "oct") JWK. Such a key cannot be
// marshaled into a servable JWKS document (see MarshalJSON).
func FromHMACSecret(secret []byte, kid ...string) Key {
	return Key{
		Kty: KeyTypeOct,
		Kid: option.FirstString(kid),
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

		size := (c.Params().BitSize + 7) / 8

		x, y := k.x, k.y
		if len(x) != size || len(y) != size {
			return nil, ErrMalformedKey
		}

		uncompressed := make([]byte, 0, 1+2*size)
		uncompressed = append(uncompressed, 4)
		uncompressed = append(uncompressed, x...)
		uncompressed = append(uncompressed, y...)

		pub, err := ecdsa.ParseUncompressedPublicKey(c, uncompressed)
		if err != nil {
			return nil, ErrMalformedKey
		}

		return pub, nil
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

// verifierForAlg builds a Verifier for alg, enforcing the key's own usage
// constraints (permitsVerify) and the anti-confusion rule that the key's type
// must match the algorithm family (spec §4.10).
func (k Key) verifierForAlg(alg Algorithm) (Verifier, error) {
	if err := k.permitsVerify(alg); err != nil {
		return nil, err
	}

	switch internalalg.FamilyOf(string(alg)) {
	case internalalg.FamilyHMAC:
		secret, err := k.Secret()
		if err != nil {
			return nil, ErrAlgorithmNotAllowed
		}

		return NewHMACVerifier(alg, secret, k.Kid)
	case internalalg.FamilyRSAPSS:
		pub, err := k.rsaPublic()
		if err != nil {
			return nil, err
		}

		return NewRSAPSSVerifier(alg, pub, k.Kid)
	case internalalg.FamilyRSAPKCS1:
		pub, err := k.rsaPublic()
		if err != nil {
			return nil, err
		}

		return NewRSAPKCS1Verifier(alg, pub, k.Kid)
	case internalalg.FamilyECDSA:
		if k.Kty != KeyTypeEC {
			return nil, ErrAlgorithmNotAllowed
		}

		pub, err := k.PublicKey()
		if err != nil {
			return nil, err
		}

		return NewECDSAVerifier(alg, pub.(*ecdsa.PublicKey), k.Kid)
	case internalalg.FamilyEdDSA:
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

// permitsVerify reports ErrKeyUsage unless the key may verify an alg
// signature: "use", when present, must be "sig" (RFC 7517 §4.2); "key_ops",
// when present, must include "verify" (§4.3); and "alg", when present, must
// equal alg (§4.4, RFC 8725 §3.1).
func (k Key) permitsVerify(alg Algorithm) error {
	if k.Use != "" && k.Use != "sig" {
		return fmt.Errorf("%w: key use is %q, not \"sig\"", ErrKeyUsage, k.Use)
	}

	if len(k.KeyOps) > 0 && !slices.Contains(k.KeyOps, "verify") {
		return fmt.Errorf("%w: key_ops %q does not include \"verify\"", ErrKeyUsage, k.KeyOps)
	}

	if k.Alg != "" && Algorithm(k.Alg) != alg {
		return fmt.Errorf("%w: key is for %q, token uses %q", ErrKeyUsage, k.Alg, alg)
	}

	return nil
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

// ParsePKCS8PrivateKey parses a DER-encoded PKCS#8 private key.
func ParsePKCS8PrivateKey(der []byte) (crypto.Signer, error) {
	return internalkeyparse.ParsePKCS8PrivateKey(der)
}

// ParsePKCS1PrivateKey parses a DER-encoded PKCS#1 RSA private key.
func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return internalkeyparse.ParsePKCS1PrivateKey(der)
}

// ParseSEC1ECPrivateKey parses a DER-encoded SEC1 EC private key.
func ParseSEC1ECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	return internalkeyparse.ParseSEC1ECPrivateKey(der)
}

// ParsePKIXPublicKey parses a DER-encoded PKIX public key.
func ParsePKIXPublicKey(der []byte) (crypto.PublicKey, error) {
	return internalkeyparse.ParsePKIXPublicKey(der)
}

// ParseEd25519PrivateKeySeed parses a raw Ed25519 seed.
func ParseEd25519PrivateKeySeed(seed []byte) (ed25519.PrivateKey, error) {
	return internalkeyparse.ParseEd25519PrivateKeySeed(seed)
}

// ParseEd25519PrivateKeyExpanded parses a raw expanded Ed25519 private key.
func ParseEd25519PrivateKeyExpanded(raw []byte) (ed25519.PrivateKey, error) {
	return internalkeyparse.ParseEd25519PrivateKeyExpanded(raw)
}

// ParseEd25519PublicKey parses a raw Ed25519 public key.
func ParseEd25519PublicKey(raw []byte) (ed25519.PublicKey, error) {
	return internalkeyparse.ParseEd25519PublicKey(raw)
}

// ParseOpenSSHPrivateKey parses an unencrypted OpenSSH private key blob.
func ParseOpenSSHPrivateKey(raw []byte) (crypto.Signer, error) {
	return internalkeyparse.ParseOpenSSHPrivateKey(raw)
}
