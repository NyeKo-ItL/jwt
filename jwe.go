package jwt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// KeyAlgorithm identifies a JWE key-management algorithm (RFC 7518 §4). Like
// Algorithm it is an open string type; the built-in constructors cover only
// the modern AEAD-friendly set (spec §3.1).
type KeyAlgorithm string

const (
	ECDHES       KeyAlgorithm = "ECDH-ES"        // direct key agreement
	ECDHESA256KW KeyAlgorithm = "ECDH-ES+A256KW" // key agreement + AES key wrap
	RSAOAEP256   KeyAlgorithm = "RSA-OAEP-256"   // RSA-OAEP with SHA-256 only
	A256KW       KeyAlgorithm = "A256KW"         // AES-256 Key Wrap
	Direct       KeyAlgorithm = "dir"            // pre-shared symmetric CEK
)

// ContentAlgorithm identifies a JWE content-encryption algorithm (RFC 7518
// §5). Only the AES-GCM family is offered (spec §3.1).
type ContentAlgorithm string

const (
	A128GCM ContentAlgorithm = "A128GCM"
	A192GCM ContentAlgorithm = "A192GCM"
	A256GCM ContentAlgorithm = "A256GCM"
)

// ErrDecryptionFailed is the single, generic error every decryption failure
// resolves to: a bad tag, a bad wrapped key, a malformed token or an
// algorithm mismatch are deliberately indistinguishable (spec §4.7).
var ErrDecryptionFailed = errors.New("jwt: decryption failed")

// Encrypter produces a compact JWE (RFC 7516 §7.1).
type Encrypter interface {
	KeyAlgorithm() KeyAlgorithm
	ContentAlgorithm() ContentAlgorithm
	KeyID() string
	Encrypt(plaintext []byte) (compact string, err error)
}

// Decrypter consumes a compact JWE. It fails closed: the AEAD tag is checked
// before any plaintext is returned, and every failure yields
// ErrDecryptionFailed.
type Decrypter interface {
	KeyID() string
	Decrypt(ctx context.Context, compact string) (plaintext []byte, err error)
}

// jweHeader is the JWE protected header (RFC 7516 §4).
type jweHeader struct {
	Alg KeyAlgorithm     `json:"alg"`
	Enc ContentAlgorithm `json:"enc"`
	Kid string           `json:"kid,omitempty"`
	EPK *Key             `json:"epk,omitempty"` // ECDH-ES ephemeral public key
	APU string           `json:"apu,omitempty"`
	APV string           `json:"apv,omitempty"`
}

// keyWrapper is the per-algorithm key-management step used when encrypting.
type keyWrapper interface {
	keyAlg() KeyAlgorithm
	// wrap derives the content-encryption key of cekLen bytes, returns the
	// JWE "encrypted_key" octets (empty for direct modes) and may add fields
	// (e.g. "epk") to hdr.
	wrap(hdr *jweHeader, cekLen int) (cek, encryptedKey []byte, err error)
}

// keyUnwrapper is the per-algorithm key-management step used when decrypting.
type keyUnwrapper interface {
	supports(alg KeyAlgorithm) bool
	unwrap(hdr *jweHeader, encryptedKey []byte, cekLen int) (cek []byte, err error)
}

type encrypter struct {
	alg     KeyAlgorithm
	enc     ContentAlgorithm
	kid     string
	wrapper keyWrapper
}

func newEncrypter(enc ContentAlgorithm, kid string, w keyWrapper) (Encrypter, error) {
	if contentKeyLen(enc) == 0 {
		return nil, fmt.Errorf("%w: unsupported content algorithm %q", ErrUnsupportedAlgorithm, enc)
	}
	return &encrypter{alg: w.keyAlg(), enc: enc, kid: kid, wrapper: w}, nil
}

func (e *encrypter) KeyAlgorithm() KeyAlgorithm         { return e.alg }
func (e *encrypter) ContentAlgorithm() ContentAlgorithm { return e.enc }
func (e *encrypter) KeyID() string                      { return e.kid }

func (e *encrypter) Encrypt(plaintext []byte) (string, error) {
	cekLen := contentKeyLen(e.enc)
	hdr := jweHeader{Alg: e.alg, Enc: e.enc, Kid: e.kid}
	cek, encryptedKey, err := e.wrapper.wrap(&hdr, cekLen)
	if err != nil {
		return "", err
	}
	protectedJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	protected := b64.Encode(protectedJSON)

	gcm, err := newGCM(cek)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, []byte(protected))
	ciphertext, tag := sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():]

	return strings.Join([]string{
		protected,
		b64.Encode(encryptedKey),
		b64.Encode(iv),
		b64.Encode(ciphertext),
		b64.Encode(tag),
	}, "."), nil
}

type decrypter struct {
	kid       string
	unwrapper keyUnwrapper
}

func (d *decrypter) KeyID() string { return d.kid }

func (d *decrypter) Decrypt(_ context.Context, compact string) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, ErrDecryptionFailed
	}
	protectedJSON, err := b64.Decode(parts[0])
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	var hdr jweHeader
	if err := json.Unmarshal(protectedJSON, &hdr); err != nil {
		return nil, ErrDecryptionFailed
	}
	cekLen := contentKeyLen(hdr.Enc)
	if cekLen == 0 || !d.unwrapper.supports(hdr.Alg) {
		return nil, ErrDecryptionFailed
	}

	encryptedKey, e1 := b64.Decode(parts[1])
	iv, e2 := b64.Decode(parts[2])
	ciphertext, e3 := b64.Decode(parts[3])
	tag, e4 := b64.Decode(parts[4])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return nil, ErrDecryptionFailed
	}

	cek, err := d.unwrapper.unwrap(&hdr, encryptedKey, cekLen)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	gcm, err := newGCM(cek)
	if err != nil || len(iv) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
		return nil, ErrDecryptionFailed
	}
	plaintext, err := gcm.Open(nil, iv, append(ciphertext, tag...), []byte(parts[0]))
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func contentKeyLen(enc ContentAlgorithm) int {
	switch enc {
	case A128GCM:
		return 16
	case A192GCM:
		return 24
	case A256GCM:
		return 32
	default:
		return 0
	}
}

func newGCM(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptClaims is the JWE analogue of Sign: JSON-marshal claims and encrypt
// them as a compact JWE.
func EncryptClaims[T any](claims Claims[T], enc Encrypter) (string, error) {
	if enc == nil {
		return "", fmt.Errorf("%w: nil Encrypter", ErrUnsupportedAlgorithm)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return enc.Encrypt(payload)
}

// DecryptClaims is the JWE analogue of Parse: decrypt a compact JWE, then
// unmarshal and validate its registered claims per opts. The AEAD tag is
// verified before any plaintext is exposed (spec §4.7). Header "typ"
// checking (WithRequiredType) does not apply here.
func DecryptClaims[T any](ctx context.Context, compact string, dec Decrypter, opts ...ParseOption) (*Claims[T], error) {
	if dec == nil {
		return nil, fmt.Errorf("%w: nil Decrypter", ErrUnsupportedAlgorithm)
	}
	payload, err := dec.Decrypt(ctx, compact)
	if err != nil {
		return nil, err
	}
	var claims Claims[T]
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload JSON: %w", ErrMalformedToken, err)
	}
	cfg := parseConfig{now: time.Now}
	for _, o := range opts {
		o(&cfg)
	}
	if err := validateClaims(payload, &claims.RegisteredClaims, Header{}, cfg); err != nil {
		return nil, err
	}
	return &claims, nil
}
