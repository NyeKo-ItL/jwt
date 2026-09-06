package jwt

import "fmt"

type directWrapper struct{ cek []byte }

func (directWrapper) keyAlg() KeyAlgorithm { return Direct }

func (w directWrapper) wrap(hdr *jweHeader, cekLen int) (cek, encryptedKey []byte, err error) {
	if len(w.cek) != cekLen {
		return nil, nil, fmt.Errorf("%w: dir CEK is %d bytes, %s needs %d", ErrMalformedKey, len(w.cek), hdr.Enc, cekLen)
	}
	return w.cek, nil, nil
}

type directUnwrapper struct{ cek []byte }

func (directUnwrapper) supports(alg KeyAlgorithm) bool { return alg == Direct }

func (u directUnwrapper) unwrap(_ *jweHeader, encryptedKey []byte, cekLen int) ([]byte, error) {
	if len(encryptedKey) != 0 || len(u.cek) != cekLen {
		return nil, ErrDecryptionFailed
	}
	return u.cek, nil
}

// NewDirectEncrypter uses a pre-shared content-encryption key directly (JWE
// "alg":"dir"). The key length must match content (16/24/32 bytes for
// A128/A192/A256GCM).
func NewDirectEncrypter(cek []byte, content ContentAlgorithm, kid string) (Encrypter, error) {
	if n := contentKeyLen(content); n == 0 || len(cek) != n {
		return nil, fmt.Errorf("%w: dir key must be %d bytes for %s, got %d", ErrMalformedKey, contentKeyLen(content), content, len(cek))
	}
	return newEncrypter(content, kid, directWrapper{cek: append([]byte(nil), cek...)})
}

// NewDirectDecrypter decrypts JWE "alg":"dir" tokens with a pre-shared CEK.
func NewDirectDecrypter(cek []byte, kid string) (Decrypter, error) {
	if len(cek) != 16 && len(cek) != 24 && len(cek) != 32 {
		return nil, fmt.Errorf("%w: dir key must be 16, 24 or 32 bytes, got %d", ErrMalformedKey, len(cek))
	}
	return &decrypter{kid: kid, unwrapper: directUnwrapper{cek: append([]byte(nil), cek...)}}, nil
}
