package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"testing"
)

func TestParsePKCS8PrivateKey(t *testing.T) {
	tk := newTestKeys(t)
	for name, key := range map[string]crypto.Signer{
		"rsa":     tk.rsa2048,
		"ecdsa":   tk.p256,
		"ed25519": tk.edPriv,
	} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		got, err := ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if !got.Public().(interface{ Equal(x crypto.PublicKey) bool }).Equal(key.Public()) {
			t.Fatalf("%s: public key mismatch", name)
		}
	}
	if _, err := ParsePKCS8PrivateKey([]byte("garbage")); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("garbage err = %v", err)
	}
}

func TestParsePKCS1PrivateKey(t *testing.T) {
	tk := newTestKeys(t)
	der := x509.MarshalPKCS1PrivateKey(tk.rsa2048)
	got, err := ParsePKCS1PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(tk.rsa2048.N) != 0 {
		t.Fatal("modulus mismatch")
	}
	if _, err := ParsePKCS1PrivateKey([]byte("nope")); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseSEC1ECPrivateKey(t *testing.T) {
	tk := newTestKeys(t)
	der, err := x509.MarshalECPrivateKey(tk.p384)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSEC1ECPrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(tk.p384) {
		t.Fatal("scalar mismatch")
	}
	if _, err := ParseSEC1ECPrivateKey([]byte("nope")); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestParsePKIXPublicKey(t *testing.T) {
	tk := newTestKeys(t)
	for name, pub := range map[string]crypto.PublicKey{
		"rsa":     &tk.rsa2048.PublicKey,
		"ecdsa":   &tk.p256.PublicKey,
		"ed25519": tk.edPub,
	} {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := ParsePKIXPublicKey(der); err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
	}
	if _, err := ParsePKIXPublicKey([]byte("nope")); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseEd25519Raw(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()

	fromSeed, err := ParseEd25519PrivateKeySeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !fromSeed.Equal(priv) {
		t.Fatal("seed round trip mismatch")
	}

	fromExpanded, err := ParseEd25519PrivateKeyExpanded(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !fromExpanded.Equal(priv) {
		t.Fatal("expanded round trip mismatch")
	}

	gotPub, err := ParseEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !gotPub.Equal(pub) {
		t.Fatal("public round trip mismatch")
	}

	// negatives
	if _, err := ParseEd25519PrivateKeySeed(seed[:31]); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short seed err = %v", err)
	}
	if _, err := ParseEd25519PrivateKeyExpanded(priv[:63]); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short expanded err = %v", err)
	}
	if _, err := ParseEd25519PublicKey(pub[:31]); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("short pub err = %v", err)
	}
	bad := append(ed25519.PrivateKey(nil), priv...)
	bad[40] ^= 0xff // corrupt the appended public half
	if _, err := ParseEd25519PrivateKeyExpanded(bad); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("inconsistent expanded err = %v", err)
	}
}

// Real keys produced by `ssh-keygen -N ” -f k -t <type>`.
const (
	opensshEd25519 = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB1K9upj2IBhIjFUG0+sxu17Os6YmUx0Rks6g9Cg8obCAAAAIhvicqtb4nK
rQAAAAtzc2gtZWQyNTUxOQAAACB1K9upj2IBhIjFUG0+sxu17Os6YmUx0Rks6g9Cg8obCA
AAAEA19qK7ITh+9spYCC17NVomz3BtParkEX7FmqSWUcdX83Ur26mPYgGEiMVQbT6zG7Xs
6zpiZTHRGSzqD0KDyhsIAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----`

	opensshRSA = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxASXRvLtwMMLQu5qoEUgXEFEnILabbUNw9utfHraM3S0fOEjY9Kt
ZA4HOQxSGcneNF4qTAyEurVfPIezEKbxwbyg3yt4fx1ALZuLtARk8ODo0UahxE9eN/odPT
7J8+3HupP/ggWzOp5uB63j10P4mL+6oA1rwTVXJG4fiet54xqzJvQekq0/gyz89GILfE22
Y7HsAy9YuKxhMnLBQWPhVsLgWW5Az5FxSlST7vwjlpUciBnzTEPm+X797NhcQkAQ6tmxMe
dC2TYXqh2XIfJmfw6GEG/0xepZVHirYWSFcttCcxUrv6i+EY0zudTdznsEbd6u4h0nuzJB
NO2PkdGV+QAAA8CijBfZoowX2QAAAAdzc2gtcnNhAAABAQDEBJdG8u3AwwtC7mqgRSBcQU
ScgtpttQ3D2618etozdLR84SNj0q1kDgc5DFIZyd40XipMDIS6tV88h7MQpvHBvKDfK3h/
HUAtm4u0BGTw4OjRRqHET143+h09Psnz7ce6k/+CBbM6nm4HrePXQ/iYv7qgDWvBNVckbh
+J63njGrMm9B6SrT+DLPz0Ygt8TbZjsewDL1i4rGEycsFBY+FWwuBZbkDPkXFKVJPu/COW
lRyIGfNMQ+b5fv3s2FxCQBDq2bEx50LZNheqHZch8mZ/DoYQb/TF6llUeKthZIVy20JzFS
u/qL4RjTO51N3OewRt3q7iHSe7MkE07Y+R0ZX5AAAAAwEAAQAAAQEAp6w1qx8KeSVecLZ4
xvfaoo/CHQ9hwQ5q4+r6D80W8YUXDuuW1kDUyQ2m6Am+AQlI5grWq47Zysxy1thNOCVWD5
9HDR+mRzXCPEEd07MelV4OSVXd8orh0YhFkqovHlV70AHhQluV4MK85By/FNizwhXfkiFo
1zDFhggdOmEPNk+SpeSojjyjCKwVMOisJ88ZCnYqxpmS639P7+qVzwsXuuB/LgclWoEiMn
YVE6G5UXinBGZlpXa75FmcaGSmfyLrLBd9RBfs1uclInMM4j/oEcJc09+/B///Fa1rZqHu
uhhBkaTFwgln+9rKx4zuqKBJgT/UDZEwpuosuIrFewKxcQAAAIAJBhCfOw9t+a05VZ89fT
VvLPgvP+dRfTvaZLIJJEaontJOAg8CwwnNT3230NFlsgqK+/6lVZmrrXiQxi4N9f8isgNe
9G3bpv9UD+fdtMyOyVQCvsyT81JaU0YIF5nL0p/zO4O5/1JFcLrreETn9j5QcEMg6uun27
JPbkH334QRZAAAAIEA++h6CNSGlxTiZuXFCtBlrLwVrsXctTMNcR5sC1xxrWO5nAcZ+iqE
4qcP1qPBtiMCyXoxYPtmRd63zNecGsUfISI9RDKe5RHdnhZd2iglKFmk26OHV+In/5mj60
KntluCYtq7J2VIE6tPCxN5x3cIPQG80TmStoEOgjkQguElHoMAAACBAMczs/o4gq1NSdjV
ZS0qZyExUoeY9mNGaOi9H2YCUF7Y+CkOlnT/JQMoyvFhjhBaQ5Os1fLxxTzh6KIyLrBriC
qWPTdn/z4g+ka3iBDnHKKVhOzeEJWMQCKmVYpFb/mwDoggzqrWCw+t7LwMAhpRBgM8q7bo
1PnuMcIA7O6PpdDTAAAABHRlc3QBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----`

	opensshECDSA = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSHmBqgVzjkoAOB97DOki6XYKuHZYKK
s+YBlZx53pgHAmg3fNH11mz7lKgoVtNmJ+i4cKO2zLeduXkU5wXL+lAsAAAAoPWOVZH1jl
WRAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIeYGqBXOOSgA4H3
sM6SLpdgq4dlgoqz5gGVnHnemAcCaDd80fXWbPuUqChW02Yn6Lhwo7bMt525eRTnBcv6UC
wAAAAhAIQfDYJDaxMSIohjacvXOQSOPP4F0E1e08KZSUOphf+zAAAABHRlc3QBAgM=
-----END OPENSSH PRIVATE KEY-----`
)

func opensshDER(t *testing.T, blk string) []byte {
	t.Helper()
	p, _ := pem.Decode([]byte(blk))
	if p == nil {
		t.Fatal("pem decode failed")
	}
	return p.Bytes
}

func TestParseOpenSSHPrivateKey(t *testing.T) {
	cases := []struct {
		name string
		pem  string
		want any
	}{
		{"ed25519", opensshEd25519, ed25519.PrivateKey{}},
		{"rsa", opensshRSA, &rsa.PrivateKey{}},
		{"ecdsa", opensshECDSA, &ecdsa.PrivateKey{}},
	}
	msg := []byte("openssh round trip")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signer, err := ParseOpenSSHPrivateKey(opensshDER(t, c.pem))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			switch c.want.(type) {
			case ed25519.PrivateKey:
				if _, ok := signer.(ed25519.PrivateKey); !ok {
					t.Fatalf("got %T", signer)
				}
				sig := ed25519.Sign(signer.(ed25519.PrivateKey), msg)
				if !ed25519.Verify(signer.Public().(ed25519.PublicKey), msg, sig) {
					t.Fatal("signature did not verify")
				}
			case *rsa.PrivateKey:
				k, ok := signer.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("got %T", signer)
				}
				if err := k.Validate(); err != nil {
					t.Fatalf("invalid RSA key: %v", err)
				}
			case *ecdsa.PrivateKey:
				k, ok := signer.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("got %T", signer)
				}
				if _, err := k.PublicKey.Bytes(); err != nil {
					t.Fatalf("public point invalid: %v", err)
				}
				h := msg
				r, s, err := ecdsa.Sign(rand.Reader, k, h)
				if err != nil {
					t.Fatal(err)
				}
				if !ecdsa.Verify(&k.PublicKey, h, r, s) {
					t.Fatal("signature did not verify")
				}
			}
		})
	}
}

func TestParseOpenSSHPrivateKeyRejects(t *testing.T) {
	if _, err := ParseOpenSSHPrivateKey([]byte("not openssh")); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("bad magic err = %v", err)
	}
	if _, err := ParseOpenSSHPrivateKey([]byte(opensshMagic + "\x00\x00")); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("truncated err = %v", err)
	}
	// flip the ciphername to something non-"none"
	der := opensshDER(t, opensshEd25519)
	enc := append([]byte(nil), der...)
	// ciphername sits right after the 15-byte magic as a length-prefixed
	// string "none"; turn it into "aead".
	copy(enc[len(opensshMagic)+4:], []byte("aead"))
	if _, err := ParseOpenSSHPrivateKey(enc); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("encrypted-key err = %v", err)
	}
}

// ---- synthetic openssh-key-v1 blobs for edge cases --------------------

func sshString(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

func buildOpenSSHBlob(t *testing.T, cipher, kdf string, count uint32, keyType string, pubBody, privBody []byte, mismatchCheck bool) []byte {
	t.Helper()
	pub := append(sshString([]byte(keyType)), pubBody...)

	priv := []byte{1, 2, 3, 4}
	if mismatchCheck {
		priv = append(priv, 9, 9, 9, 9)
	} else {
		priv = append(priv, 1, 2, 3, 4)
	}
	priv = append(priv, sshString([]byte(keyType))...)
	priv = append(priv, privBody...)
	priv = append(priv, sshString([]byte("comment"))...)
	for i := byte(1); len(priv)%8 != 0; i++ {
		priv = append(priv, i)
	}

	out := []byte(opensshMagic)
	out = append(out, sshString([]byte(cipher))...)
	out = append(out, sshString([]byte(kdf))...)
	out = append(out, sshString(nil)...)
	out = binary.BigEndian.AppendUint32(out, count)
	out = append(out, sshString(pub)...)
	out = append(out, sshString(priv)...)
	return out
}

func TestParseOpenSSHSyntheticEdgeCases(t *testing.T) {
	t.Run("unsupported key type", func(t *testing.T) {
		blob := buildOpenSSHBlob(t, "none", "none", 1, "ssh-dss", nil, nil, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("multiple keys", func(t *testing.T) {
		blob := buildOpenSSHBlob(t, "none", "none", 2, "ssh-ed25519", nil, nil, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("check integer mismatch", func(t *testing.T) {
		blob := buildOpenSSHBlob(t, "none", "none", 1, "ssh-ed25519", nil, nil, true)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("ed25519 wrong private length", func(t *testing.T) {
		body := append(sshString(make([]byte, 32)), sshString(make([]byte, 10))...)
		blob := buildOpenSSHBlob(t, "none", "none", 1, "ssh-ed25519", make([]byte, 32), body, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("ecdsa bad point", func(t *testing.T) {
		body := append(sshString([]byte("nistp256")), sshString([]byte{4, 1, 2})...)
		body = append(body, sshString([]byte{1})...) // d
		blob := buildOpenSSHBlob(t, "none", "none", 1, "ecdsa-sha2-nistp256", nil, body, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("ecdsa unknown curve", func(t *testing.T) {
		body := append(sshString([]byte("nistp999")), sshString(make([]byte, 65))...)
		body = append(body, sshString([]byte{1})...)
		blob := buildOpenSSHBlob(t, "none", "none", 1, "ecdsa-sha2-nistp256", nil, body, false)
		if _, err := ParseOpenSSHPrivateKey(blob); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestParseOpenSSHSyntheticP384AndP521(t *testing.T) {
	for _, tc := range []struct {
		curveID string
		curve   elliptic.Curve
	}{
		{"nistp384", elliptic.P384()},
		{"nistp521", elliptic.P521()},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		point, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		scalar, err := key.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		body := append(sshString([]byte(tc.curveID)), sshString(point)...)
		body = append(body, sshString(scalar)...)
		blob := buildOpenSSHBlob(t, "none", "none", 1, "ecdsa-sha2-"+tc.curveID, nil, body, false)

		got, err := ParseOpenSSHPrivateKey(blob)
		if err != nil {
			t.Fatalf("%s: %v", tc.curveID, err)
		}
		if !got.(*ecdsa.PrivateKey).Equal(key) {
			t.Fatalf("%s: scalar mismatch", tc.curveID)
		}
	}
}
