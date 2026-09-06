package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// This file parses key material from explicit, caller-decoded bytes. Every
// function is pure: no file I/O, no format auto-detection (spec §0.7, §5.9).
// The caller PEM-, hex- or base64-decodes on its own and passes the exact
// encoding named by the function to the matching parser.

// ParsePKCS8PrivateKey parses a DER-encoded PKCS#8 private key, returning the
// concrete key type embedded (*rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey), all of which satisfy crypto.Signer.
func ParsePKCS8PrivateKey(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: PKCS#8: %v", ErrMalformedKey, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: PKCS#8 key of type %T is not a signer", ErrMalformedKey, key)
	}
	return signer, nil
}

// ParsePKCS1PrivateKey parses a DER-encoded PKCS#1 RSA private key.
func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: PKCS#1: %v", ErrMalformedKey, err)
	}
	return key, nil
}

// ParseSEC1ECPrivateKey parses a DER-encoded SEC1 EC private key.
func ParseSEC1ECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: SEC1: %v", ErrMalformedKey, err)
	}
	return key, nil
}

// ParsePKIXPublicKey parses a DER-encoded PKIX (SubjectPublicKeyInfo) public
// key (RSA, EC or Ed25519).
func ParsePKIXPublicKey(der []byte) (crypto.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: PKIX: %v", ErrMalformedKey, err)
	}
	return key, nil
}

// ParseEd25519PrivateKeySeed parses a raw 32-byte Ed25519 seed.
func ParseEd25519PrivateKeySeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: Ed25519 seed must be %d bytes, got %d", ErrMalformedKey, ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ParseEd25519PrivateKeyExpanded parses a raw 64-byte expanded Ed25519 key
// (32-byte seed followed by the 32-byte public key), verifying the two
// halves are consistent.
func ParseEd25519PrivateKeyExpanded(raw []byte) (ed25519.PrivateKey, error) {
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: expanded Ed25519 key must be %d bytes, got %d", ErrMalformedKey, ed25519.PrivateKeySize, len(raw))
	}
	derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if !bytes.Equal(derived, raw) {
		return nil, fmt.Errorf("%w: expanded Ed25519 key halves are inconsistent", ErrMalformedKey)
	}
	return append(ed25519.PrivateKey(nil), raw...), nil
}

// ParseEd25519PublicKey parses a raw 32-byte Ed25519 public key.
func ParseEd25519PublicKey(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key must be %d bytes, got %d", ErrMalformedKey, ed25519.PublicKeySize, len(raw))
	}
	return append(ed25519.PublicKey(nil), raw...), nil
}

// ---- OpenSSH private key wire format (openssh-key-v1) --------------------
//
// Parsed here directly rather than via golang.org/x/crypto/ssh to keep the
// module free of third-party dependencies (spec §7). Only unencrypted keys
// are supported: the caller owns passphrase handling (spec §0.7).

const opensshMagic = "openssh-key-v1\x00"

// ParseOpenSSHPrivateKey parses the OpenSSH private key binary format (the
// bytes inside the "-----BEGIN OPENSSH PRIVATE KEY-----" PEM block, already
// base64-decoded by the caller). Encrypted keys are rejected.
func ParseOpenSSHPrivateKey(raw []byte) (crypto.Signer, error) {
	if !bytes.HasPrefix(raw, []byte(opensshMagic)) {
		return nil, fmt.Errorf("%w: not an openssh-key-v1 blob", ErrMalformedKey)
	}
	r := &sshBuf{b: raw[len(opensshMagic):]}
	cipher := string(r.str())
	kdf := string(r.str())
	r.str() // kdf options
	count := r.u32()
	r.str() // public key
	priv := r.str()
	if r.err != nil {
		return nil, fmt.Errorf("%w: truncated OpenSSH header: %v", ErrMalformedKey, r.err)
	}
	if cipher != "none" || kdf != "none" {
		return nil, fmt.Errorf("%w: encrypted OpenSSH keys are not supported", ErrMalformedKey)
	}
	if count != 1 {
		return nil, fmt.Errorf("%w: OpenSSH blob holds %d keys, want 1", ErrMalformedKey, count)
	}

	p := &sshBuf{b: priv}
	if p.u32() != p.u32() {
		return nil, fmt.Errorf("%w: OpenSSH check integers differ (wrong passphrase or corrupt)", ErrMalformedKey)
	}
	keyType := string(p.str())
	signer, err := parseOpenSSHKeyBody(keyType, p)
	if err != nil {
		return nil, err
	}
	if p.err != nil {
		return nil, fmt.Errorf("%w: truncated OpenSSH private section: %v", ErrMalformedKey, p.err)
	}
	return signer, nil
}

func parseOpenSSHKeyBody(keyType string, p *sshBuf) (crypto.Signer, error) {
	switch keyType {
	case "ssh-ed25519":
		p.str() // public key (32 bytes)
		priv := p.str()
		if p.err != nil {
			return nil, fmt.Errorf("%w: OpenSSH Ed25519: %v", ErrMalformedKey, p.err)
		}
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: OpenSSH Ed25519 private key is %d bytes", ErrMalformedKey, len(priv))
		}
		return append(ed25519.PrivateKey(nil), priv...), nil

	case "ssh-rsa":
		n := p.mpint()
		e := p.mpint()
		d := p.mpint()
		p.mpint() // iqmp (recomputed by Precompute)
		primeP := p.mpint()
		primeQ := p.mpint()
		if p.err != nil {
			return nil, fmt.Errorf("%w: OpenSSH RSA: %v", ErrMalformedKey, p.err)
		}
		key := &rsa.PrivateKey{
			N: n, E: int(e.Int64()),
			D:      d,
			Primes: []*big.Int{primeP, primeQ},
		}
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("%w: OpenSSH RSA: %v", ErrMalformedKey, err)
		}
		key.Precompute()
		return key, nil

	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		curveID := string(p.str())
		point := p.str()
		d := p.mpint()
		if p.err != nil {
			return nil, fmt.Errorf("%w: OpenSSH ECDSA: %v", ErrMalformedKey, p.err)
		}
		curve := sshCurve(curveID)
		if curve == nil {
			return nil, fmt.Errorf("%w: unknown OpenSSH EC curve %q", ErrMalformedKey, curveID)
		}
		x, y, err := uncompressedPoint(curve, point)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PrivateKey{
			Curve: curve, X: x, Y: y,
			D: d,
		}, nil

	default:
		return nil, fmt.Errorf("%w: unsupported OpenSSH key type %q", ErrMalformedKey, keyType)
	}
}

func sshCurve(id string) elliptic.Curve {
	switch id {
	case "nistp256":
		return elliptic.P256()
	case "nistp384":
		return elliptic.P384()
	case "nistp521":
		return elliptic.P521()
	default:
		return nil
	}
}

// uncompressedPoint decodes an SEC1 uncompressed point (0x04 || X || Y)
// without the deprecated elliptic.Unmarshal.
func uncompressedPoint(curve elliptic.Curve, b []byte) (x, y *big.Int, err error) {
	size := (curve.Params().BitSize + 7) / 8
	if len(b) != 1+2*size || b[0] != 4 {
		return nil, nil, fmt.Errorf("%w: malformed EC point", ErrMalformedKey)
	}
	return new(big.Int).SetBytes(b[1 : 1+size]), new(big.Int).SetBytes(b[1+size:]), nil
}

// sshBuf reads the SSH wire types (RFC 4251 §5) from a byte slice, latching
// the first error so callers can check once at the end.
type sshBuf struct {
	b   []byte
	err error
}

var errSSHShort = errors.New("short buffer")

func (r *sshBuf) u32() uint32 {
	if r.err != nil {
		return 0
	}
	if len(r.b) < 4 {
		r.err = errSSHShort
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *sshBuf) str() []byte {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(len(r.b)) {
		r.err = errSSHShort
		return nil
	}
	s := r.b[:n]
	r.b = r.b[n:]
	return s
}

func (r *sshBuf) mpint() *big.Int {
	return new(big.Int).SetBytes(r.str())
}
