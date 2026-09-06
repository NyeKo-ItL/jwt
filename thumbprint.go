package jwt

import (
	"crypto"
	"fmt"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// Thumbprint computes the RFC 7638 JWK thumbprint of an already-parsed Key.
// A zero hash defaults to SHA-256 (the hash used for the "jkt" confirmation
// value). The canonical form contains only the type-specific required
// members, with keys in lexicographic order and no whitespace (RFC 7638 §3).
func Thumbprint(k Key, hash crypto.Hash) (string, error) {
	canonical, err := k.thumbprintInput()
	if err != nil {
		return "", err
	}
	return digestThumbprint(canonical, hash)
}

// ThumbprintBytes computes an RFC 7638-shaped thumbprint directly from raw
// key material the caller already holds, without a parsed Key. It supports
// the unambiguous single-blob key types: "oct" (raw is the secret) and "OKP"
// (raw is the 32-byte Ed25519 public key). RSA and EC keys have no single
// canonical byte form — use Thumbprint with a parsed Key for those.
func ThumbprintBytes(kty KeyType, raw []byte, hash crypto.Hash) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("%w: empty key material", ErrMalformedKey)
	}
	var canonical string
	switch kty {
	case KeyTypeOct:
		canonical = fmt.Sprintf(`{"k":%q,"kty":"oct"}`, b64.Encode(raw))
	case KeyTypeOKP:
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, b64.Encode(raw))
	default:
		return "", fmt.Errorf("%w: ThumbprintBytes supports only oct and OKP, not %q", ErrMalformedKey, kty)
	}
	return digestThumbprint(canonical, hash)
}

func (k Key) thumbprintInput() (string, error) {
	switch k.Kty {
	case KeyTypeRSA:
		if len(k.n) == 0 || len(k.e) == 0 {
			return "", fmt.Errorf("%w: RSA key missing n/e", ErrMalformedKey)
		}
		return fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, b64.Encode(k.e), b64.Encode(k.n)), nil
	case KeyTypeEC:
		if k.crv == "" || len(k.x) == 0 || len(k.y) == 0 {
			return "", fmt.Errorf("%w: EC key missing crv/x/y", ErrMalformedKey)
		}
		return fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.crv, b64.Encode(k.x), b64.Encode(k.y)), nil
	case KeyTypeOKP:
		if k.crv == "" || len(k.x) == 0 {
			return "", fmt.Errorf("%w: OKP key missing crv/x", ErrMalformedKey)
		}
		return fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.crv, b64.Encode(k.x)), nil
	case KeyTypeOct:
		if len(k.k) == 0 {
			return "", fmt.Errorf("%w: oct key missing k", ErrMalformedKey)
		}
		return fmt.Sprintf(`{"k":%q,"kty":"oct"}`, b64.Encode(k.k)), nil
	default:
		return "", fmt.Errorf("%w: cannot thumbprint kty %q", ErrMalformedKey, k.Kty)
	}
}

func digestThumbprint(canonical string, hash crypto.Hash) (string, error) {
	if hash == 0 {
		hash = crypto.SHA256
	}
	if !hash.Available() {
		return "", fmt.Errorf("%w: hash %v is not linked into the binary", ErrUnsupportedAlgorithm, hash)
	}
	return b64.Encode(hashSum(hash, []byte(canonical))), nil
}

// ParseKey parses a single JSON Web Key (RFC 7517 §4).
func ParseKey(data []byte) (Key, error) {
	var k Key
	if err := k.UnmarshalJSON(data); err != nil {
		return Key{}, fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	if k.Kty == "" {
		return Key{}, fmt.Errorf("%w: JWK has no \"kty\"", ErrMalformedKey)
	}
	return k, nil
}
