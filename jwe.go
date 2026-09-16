package jwt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// KeyAlgorithm identifies a JWE key-management algorithm (RFC 7518 §4). Like
// Algorithm it is an open string type; the built-in constructors cover only
// the modern AEAD-friendly set (spec §3.1).
type KeyAlgorithm string

// Built-in JWE key-management algorithms.
const (
	ECDHES       KeyAlgorithm = "ECDH-ES"        // RFC 7518 §4.6: direct key agreement (P-256/384/521)
	ECDHESA256KW KeyAlgorithm = "ECDH-ES+A256KW" // RFC 7518 §4.6: key agreement + AES-256 Key Wrap
	RSAOAEP256   KeyAlgorithm = "RSA-OAEP-256"   // RFC 7518 §4.3: RSAES-OAEP, SHA-256 and MGF1-SHA-256
	A256KW       KeyAlgorithm = "A256KW"         // RFC 7518 §4.4: AES-256 Key Wrap (RFC 3394)
	Direct       KeyAlgorithm = "dir"            // RFC 7518 §4.5: pre-shared symmetric CEK
)

// ContentAlgorithm identifies a JWE content-encryption algorithm (RFC 7518
// §5). Only the AES-GCM family is offered (spec §3.1).
type ContentAlgorithm string

// AES-GCM content encryption with a 96-bit IV and 128-bit tag (RFC 7518 §5.3).
const (
	A128GCM ContentAlgorithm = "A128GCM" // AES-128-GCM, 16-byte CEK
	A192GCM ContentAlgorithm = "A192GCM" // AES-192-GCM, 24-byte CEK
	A256GCM ContentAlgorithm = "A256GCM" // AES-256-GCM, 32-byte CEK
)

// ErrDecryptionFailed is the single, generic error every decryption failure
// resolves to: a bad tag, a bad wrapped key, a malformed token or an
// algorithm mismatch are deliberately indistinguishable (spec §4.7).
var ErrDecryptionFailed = errors.New("jwt: decryption failed")

// Encrypter produces a compact JWE (RFC 7516 §7.1).
type Encrypter interface {
	// KeyAlgorithm reports the "alg" (key-management) value written to the
	// protected header.
	KeyAlgorithm() KeyAlgorithm
	// ContentAlgorithm reports the "enc" (content-encryption) value.
	ContentAlgorithm() ContentAlgorithm
	// KeyID is the "kid" written to the header; empty if none.
	KeyID() string
	// Encrypt returns the compact JWE for plaintext.
	Encrypt(plaintext []byte) (compact string, err error)
}

// Decrypter consumes a compact JWE. It fails closed: the AEAD tag is checked
// before any plaintext is returned, and every failure yields
// ErrDecryptionFailed.
type Decrypter interface {
	// KeyID is the "kid" this decrypter's key material carries; empty if none.
	KeyID() string
	// Decrypt authenticates and decrypts compact, returning ErrDecryptionFailed
	// on any problem (bad tag, wrong key, malformed token, algorithm mismatch).
	Decrypt(ctx context.Context, compact string) (plaintext []byte, err error)
}

// jweHeader is the JWE protected header (RFC 7516 §4).
type jweHeader struct {
	Alg KeyAlgorithm     `json:"alg"`
	Enc ContentAlgorithm `json:"enc"`
	Kid string           `json:"kid,omitempty"`
	Typ string           `json:"typ,omitempty"`
	Cty string           `json:"cty,omitempty"`
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
	parts, hdr, err := parseJWEProtected(compact)
	if err != nil {
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

	// RFC 7516 §5.2 step 14: the AAD is the ASCII of the encoded protected header.
	plaintext, err := gcm.Open(nil, iv, append(ciphertext, tag...), []byte(parts[0]))
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// parseJWEProtected splits a compact JWE (RFC 7516 §7.1) and decodes and
// vets its protected header: the input is size-capped, the header must be a
// strictly decoded JSON object, "zip" is refused because compression is not
// supported (RFC 7516 §4.1.3 — which also removes any decompression-bomb
// surface), and "crit" is enforced (§4.1.13). Crit failures wrap
// ErrUnsupportedCritical; every other failure wraps ErrDecryptionFailed.
func parseJWEProtected(compact string) ([]string, jweHeader, error) {
	var hdr jweHeader

	if len(compact) > maxTokenBytes || strings.Count(compact, ".") != 4 {
		return nil, hdr, ErrDecryptionFailed
	}

	parts := strings.Split(compact, ".")

	protectedJSON, err := b64.Decode(parts[0])
	if err != nil {
		return nil, hdr, ErrDecryptionFailed
	}

	// "alg" and "enc" are both REQUIRED (RFC 7516 §4.1.1–4.1.2).
	if err := decodeObject(protectedJSON, &hdr); err != nil || hdr.Alg == "" || hdr.Enc == "" {
		return nil, hdr, ErrDecryptionFailed
	}

	members, err := headerMembers(protectedJSON)
	if err != nil {
		return nil, hdr, ErrDecryptionFailed
	}

	if _, zip := members["zip"]; zip {
		return nil, hdr, ErrDecryptionFailed
	}

	if err := checkCritical(members); err != nil {
		return nil, hdr, err
	}

	return parts, hdr, nil
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

// EncryptClaims is the JWE analogue of Sign: JSON-marshal a claims value
// (any struct that marshals to an object) and encrypt it as a compact JWE.
func EncryptClaims[C any](claims C, enc Encrypter) (string, error) {
	if enc == nil {
		return "", fmt.Errorf("%w: nil Encrypter", ErrUnsupportedAlgorithm)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	return enc.Encrypt(payload)
}

// DecryptClaims is the JWE analogue of Parse: decrypt a compact JWE, validate
// its registered claims per opts, and unmarshal the plaintext into dst (its
// type is inferred; no explicit type argument).
//
// Both JWE allowlists are mandatory (RFC 8725 §3.1, spec §4.1):
// WithAllowedKeyAlgorithms for "alg" and WithAllowedContentAlgorithms for
// "enc"; without them DecryptClaims returns ErrNoAllowedAlgorithms. They are
// checked against the protected header before dec is called, so they hold
// for caller-supplied Decrypters too. The AEAD tag is verified before any
// plaintext is exposed (spec §4.7). WithRequiredType applies to the JWE
// protected header's "typ".
func DecryptClaims[C any](ctx context.Context, compact string, dst *C, dec Decrypter, opts ...ParseOption) error {
	if dec == nil {
		return fmt.Errorf("%w: nil Decrypter", ErrUnsupportedAlgorithm)
	}

	cfg := parseConfig{now: time.Now}
	for _, o := range opts {
		o.applyParse(&cfg)
	}

	allowedAlgs, allowedEncs := withoutNone(cfg.allowedKeyAlgs), withoutNone(cfg.allowedContentAlgs)
	if len(allowedAlgs) == 0 || len(allowedEncs) == 0 {
		return fmt.Errorf("%w: DecryptClaims needs WithAllowedKeyAlgorithms and WithAllowedContentAlgorithms", ErrNoAllowedAlgorithms)
	}

	_, hdr, err := parseJWEProtected(compact)
	if err != nil {
		return err
	}

	if !slices.Contains(allowedAlgs, hdr.Alg) {
		return fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, hdr.Alg)
	}

	if !slices.Contains(allowedEncs, hdr.Enc) {
		return fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, hdr.Enc)
	}

	payload, err := dec.Decrypt(ctx, compact)
	if err != nil {
		return err
	}

	var reg RegisteredClaims
	if err := decodeObject(payload, &reg); err != nil {
		return fmt.Errorf("%w: payload JSON: %w", ErrMalformedToken, err)
	}

	if err := validateClaims(payload, &reg, Header{Type: hdr.Typ}, cfg); err != nil {
		return err
	}

	if err := decodeObject(payload, dst); err != nil {
		return fmt.Errorf("%w: payload JSON: %w", ErrMalformedToken, err)
	}

	return nil
}
