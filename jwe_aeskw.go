package jwt

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// aesKWDefaultIV is the RFC 3394 §2.2.3.1 default initial value.
var aesKWDefaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

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
	r := make([][]byte, n)
	for i := range r {
		r[i] = append([]byte(nil), plaintext[i*8:(i+1)*8]...)
	}
	a := append([]byte(nil), aesKWDefaultIV...)
	buf := make([]byte, 16)
	for j := range 6 {
		for i := range n {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			copy(a, buf[:8])
			t := uint64(n*j + i + 1)
			var tb [8]byte
			binary.BigEndian.PutUint64(tb[:], t)
			subtle.XORBytes(a, a, tb[:])
			copy(r[i], buf[8:])
		}
	}
	out := make([]byte, 0, 8+len(plaintext))
	out = append(out, a...)
	for _, ri := range r {
		out = append(out, ri...)
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
	a := append([]byte(nil), ciphertext[:8]...)
	r := make([][]byte, n)
	for i := range r {
		r[i] = append([]byte(nil), ciphertext[8+i*8:8+(i+1)*8]...)
	}
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			var tb [8]byte
			binary.BigEndian.PutUint64(tb[:], t)
			at := make([]byte, 8)
			subtle.XORBytes(at, a, tb[:])
			copy(buf[:8], at)
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, aesKWDefaultIV) != 1 {
		return nil, ErrDecryptionFailed
	}
	out := make([]byte, 0, n*8)
	for _, ri := range r {
		out = append(out, ri...)
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
	return newEncrypter(content, optKID(kid), aesKWWrapper{kek: append([]byte(nil), kek...)})
}

// NewA256KWDecrypter unwraps the CEK of a JWE "alg":"A256KW" token.
func NewA256KWDecrypter(kek []byte, kid ...string) (Decrypter, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("%w: A256KW KEK must be 32 bytes, got %d", ErrMalformedKey, len(kek))
	}
	return &decrypter{kid: optKID(kid), unwrapper: aesKWUnwrapper{kek: append([]byte(nil), kek...)}}, nil
}
