package keyparse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	internalerr "github.com/NyeKo-ItL/jwt/internal/errors"
)

func sshMPInt(n int64) []byte {
	return sshString(big.NewInt(n).Bytes())
}

func TestParseOpenSSHAdditionalErrors(t *testing.T) {
	t.Run("ed25519 truncated body", func(t *testing.T) {
		body := sshString(make([]byte, 32))

		blob := buildOpenSSHBlob(t, "none", "none", 1, "ssh-ed25519", nil, body, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, internalerr.ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("rsa truncated body", func(t *testing.T) {
		body := sshMPInt(15)

		blob := buildOpenSSHBlob(t, "none", "none", 1, "ssh-rsa", nil, body, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, internalerr.ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("rsa invalid key", func(t *testing.T) {
		// N is p*q, but D is not a valid inverse of E modulo phi(N).
		body := append(sshMPInt(15), sshMPInt(3)...)
		body = append(body, sshMPInt(3)...)
		body = append(body, sshMPInt(1)...)
		body = append(body, sshMPInt(3)...)
		body = append(body, sshMPInt(5)...)

		blob := buildOpenSSHBlob(t, "none", "none", 1, "ssh-rsa", nil, body, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, internalerr.ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("ecdsa invalid scalar", func(t *testing.T) {
		body := append(sshString([]byte("nistp256")), sshString(make([]byte, 65))...)
		body = append(body, sshMPInt(0)...)

		blob := buildOpenSSHBlob(t, "none", "none", 1, "ecdsa-sha2-nistp256", nil, body, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, internalerr.ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("ecdsa point does not match scalar", func(t *testing.T) {
		key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		point, err := key2.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}

		scalar, err := key1.Bytes()
		if err != nil {
			t.Fatal(err)
		}

		body := append(sshString([]byte("nistp256")), sshString(point)...)
		body = append(body, sshString(scalar)...)

		blob := buildOpenSSHBlob(t, "none", "none", 1, "ecdsa-sha2-nistp256", nil, body, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, internalerr.ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSSHBufShortString(t *testing.T) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], 4)

	r := &sshBuf{b: length[:3]}
	if got := r.str(); got != nil || !errors.Is(r.err, errSSHShort) {
		t.Fatalf("str() = %v, err = %v", got, r.err)
	}

	r = &sshBuf{b: append(length[:], []byte{1, 2}...)}
	if got := r.str(); got != nil || !errors.Is(r.err, errSSHShort) {
		t.Fatalf("short payload str() = %v, err = %v", got, r.err)
	}
}
