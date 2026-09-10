package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// concatKDF is the NIST SP 800-56A Concatenation KDF as profiled by RFC 7518
// §4.6, specialised to a single SHA-256 round (sufficient for <=256-bit
// outputs). apu/apv are always empty here.
func concatKDF(z []byte, algID string, keyBits int) []byte {
	var other bytes.Buffer
	writeLenPrefixed(&other, []byte(algID))                     // AlgorithmID
	writeLenPrefixed(&other, nil)                               // PartyUInfo (apu)
	writeLenPrefixed(&other, nil)                               // PartyVInfo (apv)
	_ = binary.Write(&other, binary.BigEndian, uint32(keyBits)) // SuppPubInfo
	// SuppPrivInfo: empty

	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, uint32(1)) // round counter
	h.Write(z)
	h.Write(other.Bytes())
	return h.Sum(nil)[:keyBits/8]
}

func writeLenPrefixed(buf *bytes.Buffer, b []byte) {
	_ = binary.Write(buf, binary.BigEndian, uint32(len(b)))
	buf.Write(b)
}

// ecdhZ computes the raw ECDH shared secret (the agreed X coordinate,
// big-endian, left-padded to the curve size) between priv and pub.
func ecdhZ(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	if priv.Curve != pub.Curve {
		return nil, fmt.Errorf("%w: ECDH curve mismatch", ErrDecryptionFailed)
	}
	ep, err := priv.ECDH()
	if err != nil {
		return nil, err
	}
	epub, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	return ep.ECDH(epub)
}

type ecdhWrapper struct {
	pub *ecdsa.PublicKey
	alg KeyAlgorithm // ECDHES or ECDHESA256KW
}

func (w ecdhWrapper) keyAlg() KeyAlgorithm { return w.alg }

func (w ecdhWrapper) wrap(hdr *jweHeader, cekLen int) (cek, encryptedKey []byte, err error) {
	ephemeral, err := ecdsa.GenerateKey(w.pub.Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	z, err := ecdhZ(ephemeral, w.pub)
	if err != nil {
		return nil, nil, err
	}
	epk := FromECDSAPublicKey(&ephemeral.PublicKey, "")
	hdr.EPK = &epk

	switch w.alg {
	case ECDHES:
		// direct: the agreed key IS the CEK, keyed to the content algorithm.
		return concatKDF(z, string(hdr.Enc), cekLen*8), nil, nil
	case ECDHESA256KW:
		// Key Agreement with Key Wrapping: the Concat KDF AlgorithmID is the
		// "alg" value, not the wrap algorithm (RFC 7518 §4.6.2).
		kek := concatKDF(z, string(w.alg), 256)
		cek = make([]byte, cekLen)
		if _, err = rand.Read(cek); err != nil {
			return nil, nil, err
		}
		encryptedKey, err = aesKWWrap(kek, cek)
		return cek, encryptedKey, err
	default:
		return nil, nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, w.alg)
	}
}

type ecdhUnwrapper struct{ priv *ecdsa.PrivateKey }

func (ecdhUnwrapper) supports(alg KeyAlgorithm) bool {
	return alg == ECDHES || alg == ECDHESA256KW
}

func (u ecdhUnwrapper) unwrap(hdr *jweHeader, encryptedKey []byte, cekLen int) ([]byte, error) {
	if hdr.EPK == nil {
		return nil, ErrDecryptionFailed
	}
	epub, err := hdr.EPK.PublicKey()
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	ecPub, ok := epub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrDecryptionFailed
	}
	z, err := ecdhZ(u.priv, ecPub)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	switch hdr.Alg {
	case ECDHES:
		if len(encryptedKey) != 0 {
			return nil, ErrDecryptionFailed
		}
		return concatKDF(z, string(hdr.Enc), cekLen*8), nil
	case ECDHESA256KW:
		kek := concatKDF(z, string(hdr.Alg), 256) // AlgorithmID = "alg" (RFC 7518 §4.6.2)
		cek, err := aesKWUnwrap(kek, encryptedKey)
		if err != nil || len(cek) != cekLen {
			return nil, ErrDecryptionFailed
		}
		return cek, nil
	default:
		return nil, ErrDecryptionFailed
	}
}

// NewECDHESEncrypter derives (ECDH-ES) or derives-and-wraps
// (ECDH-ES+A256KW) the CEK against an EC public key. alg must be ECDHES or
// ECDHESA256KW.
func NewECDHESEncrypter(pub *ecdsa.PublicKey, alg KeyAlgorithm, content ContentAlgorithm, kid ...string) (Encrypter, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: nil EC public key", ErrMalformedKey)
	}
	if alg != ECDHES && alg != ECDHESA256KW {
		return nil, fmt.Errorf("%w: %q is not an ECDH-ES key algorithm", ErrUnsupportedAlgorithm, alg)
	}
	if curveName(pub.Curve) == "" {
		return nil, fmt.Errorf("%w: unsupported EC curve", ErrMalformedKey)
	}
	return newEncrypter(content, optKID(kid), ecdhWrapper{pub: pub, alg: alg})
}

// NewECDHESDecrypter decrypts JWE tokens whose "alg" is ECDH-ES or
// ECDH-ES+A256KW, using an EC private key.
func NewECDHESDecrypter(priv *ecdsa.PrivateKey, kid ...string) (Decrypter, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: nil EC private key", ErrMalformedKey)
	}
	if curveName(priv.Curve) == "" {
		return nil, fmt.Errorf("%w: unsupported EC curve", ErrMalformedKey)
	}
	return &decrypter{kid: optKID(kid), unwrapper: ecdhUnwrapper{priv: priv}}, nil
}
