package jwt

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/NyeKo-ItL/jwt/internal/option"
)

// aesKWDefaultIV is the RFC 3394 §2.2.3.1 default initial value.
var aesKWDefaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKWWrap implements the RFC 3394 AES Key Wrap. plaintext must be a
// multiple of 8 bytes and at least 16.
func aesKWWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("%w: AES-KW input must be a multiple of 8 bytes (>=16)", ErrMalformedKey)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8
	out := make([]byte, len(plaintext)+8)
	copy(out[:8], aesKWDefaultIV[:])
	copy(out[8:], plaintext)

	a, r := out[:8], out[8:]
	var buf [16]byte

	for j := range 6 {
		for i := range n {
			copy(buf[:8], a)
			copy(buf[8:], r[i*8:(i+1)*8])
			block.Encrypt(buf[:], buf[:])

			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^t)
			copy(r[i*8:(i+1)*8], buf[8:])
		}
	}

	return out, nil
}

// aesKWUnwrap reverses aesKWWrap, returning an error if the integrity check
// fails.
func aesKWUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(ciphertext)/8 - 1
	out := make([]byte, len(ciphertext)-8)
	copy(out, ciphertext[8:])

	var a [8]byte
	copy(a[:], ciphertext[:8])

	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n)*uint64(j) + uint64(i) + 1 //nolint:gosec // n and i are bounded by the ciphertext size.
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(buf[8:], out[i*8:(i+1)*8])
			block.Decrypt(buf[:], buf[:])
			copy(a[:], buf[:8])
			copy(out[i*8:(i+1)*8], buf[8:])
		}
	}

	if subtle.ConstantTimeCompare(a[:], aesKWDefaultIV[:]) != 1 {
		return nil, ErrDecryptionFailed
	}

	return out, nil
}

type aesKWWrapper struct{ kek []byte }

func (aesKWWrapper) keyAlg() KeyAlgorithm { return A256KW }

func (w aesKWWrapper) wrap(_ *jweHeader, cekLen int) (cek, encryptedKey []byte, err error) {
	cek = make([]byte, cekLen)
	if _, err = rand.Read(cek); err != nil {
		return nil, nil, err
	}

	encryptedKey, err = aesKWWrap(w.kek, cek)

	return cek, encryptedKey, err
}

type aesKWUnwrapper struct{ kek []byte }

func (aesKWUnwrapper) supports(alg KeyAlgorithm) bool { return alg == A256KW }

func (u aesKWUnwrapper) unwrap(_ *jweHeader, encryptedKey []byte, cekLen int) ([]byte, error) {
	if len(encryptedKey) != cekLen+8 {
		return nil, ErrDecryptionFailed
	}

	cek, err := aesKWUnwrap(u.kek, encryptedKey)
	if err != nil || len(cek) != cekLen {
		return nil, ErrDecryptionFailed
	}

	return cek, nil
}

// NewA256KWEncrypter wraps a fresh CEK under a 256-bit key-encryption key
// (JWE "alg":"A256KW").
func NewA256KWEncrypter(kek []byte, content ContentAlgorithm, kid ...string) (Encrypter, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("%w: A256KW KEK must be 32 bytes, got %d", ErrMalformedKey, len(kek))
	}

	return newEncrypter(content, option.FirstString(kid), aesKWWrapper{kek: append([]byte(nil), kek...)})
}

// NewA256KWDecrypter unwraps the CEK of a JWE "alg":"A256KW" token.
func NewA256KWDecrypter(kek []byte, kid ...string) (Decrypter, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("%w: A256KW KEK must be 32 bytes, got %d", ErrMalformedKey, len(kek))
	}

	return &decrypter{kid: option.FirstString(kid), unwrapper: aesKWUnwrapper{kek: append([]byte(nil), kek...)}}, nil
}
