package interop

import (
	"context"
	"testing"

	jwt "github.com/NyeKo-ItL/jwt"
	jose "github.com/go-jose/go-jose/v4"
)

var jweKeyAlgs = []struct {
	name string
	our  jwt.KeyAlgorithm
	jose jose.KeyAlgorithm
}{
	{"RSA-OAEP-256", jwt.RSAOAEP256, jose.RSA_OAEP_256},
	{"ECDH-ES", jwt.ECDHES, jose.ECDH_ES},
	{"ECDH-ES+A256KW", jwt.ECDHESA256KW, jose.ECDH_ES_A256KW},
	{"A256KW", jwt.A256KW, jose.A256KW},
	{"dir", jwt.Direct, jose.DIRECT},
}

var jweContentAlgs = []struct {
	our  jwt.ContentAlgorithm
	jose jose.ContentEncryption
}{
	{jwt.A128GCM, jose.A128GCM},
	{jwt.A192GCM, jose.A192GCM},
	{jwt.A256GCM, jose.A256GCM},
}

func oursEncrypter(t *testing.T, keyAlg jwt.KeyAlgorithm, content jwt.ContentAlgorithm) jwt.Encrypter {
	t.Helper()
	var (
		e   jwt.Encrypter
		err error
	)
	switch keyAlg {
	case jwt.RSAOAEP256:
		e, err = jwt.NewRSAOAEP256Encrypter(&keys.rsa.PublicKey, content, "k")
	case jwt.ECDHES, jwt.ECDHESA256KW:
		e, err = jwt.NewECDHESEncrypter(&keys.p256.PublicKey, keyAlg, content, "k")
	case jwt.A256KW:
		e, err = jwt.NewA256KWEncrypter(keys.kek, content, "k")
	case jwt.Direct:
		e, err = jwt.NewDirectEncrypter(keys.dir[string(content)], content, "k")
	default:
		t.Fatalf("no encrypter for %s", keyAlg)
	}
	if err != nil {
		t.Fatalf("new encrypter %s/%s: %v", keyAlg, content, err)
	}
	return e
}

func oursDecrypter(t *testing.T, keyAlg jwt.KeyAlgorithm, content jwt.ContentAlgorithm) jwt.Decrypter {
	t.Helper()
	var (
		d   jwt.Decrypter
		err error
	)
	switch keyAlg {
	case jwt.RSAOAEP256:
		d, err = jwt.NewRSAOAEP256Decrypter(keys.rsa, "k")
	case jwt.ECDHES, jwt.ECDHESA256KW:
		d, err = jwt.NewECDHESDecrypter(keys.p256, "k")
	case jwt.A256KW:
		d, err = jwt.NewA256KWDecrypter(keys.kek, "k")
	case jwt.Direct:
		d, err = jwt.NewDirectDecrypter(keys.dir[string(content)], "k")
	default:
		t.Fatalf("no decrypter for %s", keyAlg)
	}
	if err != nil {
		t.Fatalf("new decrypter %s: %v", keyAlg, err)
	}
	return d
}

func joseRecipientKey(keyAlg jose.KeyAlgorithm, content jwt.ContentAlgorithm) any {
	switch keyAlg {
	case jose.RSA_OAEP_256:
		return &keys.rsa.PublicKey
	case jose.ECDH_ES, jose.ECDH_ES_A256KW:
		return &keys.p256.PublicKey
	case jose.A256KW:
		return keys.kek
	case jose.DIRECT:
		return keys.dir[string(content)]
	}
	return nil
}

func joseDecryptKey(keyAlg jose.KeyAlgorithm, content jwt.ContentAlgorithm) any {
	switch keyAlg {
	case jose.RSA_OAEP_256:
		return keys.rsa
	case jose.ECDH_ES, jose.ECDH_ES_A256KW:
		return keys.p256
	case jose.A256KW:
		return keys.kek
	case jose.DIRECT:
		return keys.dir[string(content)]
	}
	return nil
}

func TestJWE_OursDecryptedByGoJose(t *testing.T) {
	for _, k := range jweKeyAlgs {
		for _, c := range jweContentAlgs {
			t.Run(k.name+"/"+string(c.our), func(t *testing.T) {
				compact, err := jwt.EncryptClaims(jwt.Claims[payload]{
					RegisteredClaims: jwt.RegisteredClaims{Subject: "interop"},
					Custom:           payload{Marker: marker},
				}, oursEncrypter(t, k.our, c.our))
				if err != nil {
					t.Fatalf("EncryptClaims: %v", err)
				}
				jwe, err := jose.ParseEncrypted(compact,
					[]jose.KeyAlgorithm{k.jose}, []jose.ContentEncryption{c.jose})
				if err != nil {
					t.Fatalf("jose.ParseEncrypted: %v", err)
				}
				raw, err := jwe.Decrypt(joseDecryptKey(k.jose, c.our))
				if err != nil {
					t.Fatalf("jose decrypt: %v", err)
				}
				assertPayload(t, raw)
			})
		}
	}
}

func TestJWE_GoJoseDecryptedByOurs(t *testing.T) {
	for _, k := range jweKeyAlgs {
		for _, c := range jweContentAlgs {
			t.Run(k.name+"/"+string(c.our), func(t *testing.T) {
				encr, err := jose.NewEncrypter(c.jose,
					jose.Recipient{Algorithm: k.jose, Key: joseRecipientKey(k.jose, c.our)}, nil)
				if err != nil {
					t.Fatalf("jose.NewEncrypter: %v", err)
				}
				obj, err := encr.Encrypt(wantPayloadJSON(t))
				if err != nil {
					t.Fatalf("jose encrypt: %v", err)
				}
				compact, err := obj.CompactSerialize()
				if err != nil {
					t.Fatal(err)
				}
				got, err := jwt.DecryptClaims[payload](context.Background(), compact,
					oursDecrypter(t, k.our, c.our))
				if err != nil {
					t.Fatalf("jwt.DecryptClaims: %v", err)
				}
				if got.Subject != "interop" || got.Custom.Marker != marker {
					t.Fatalf("claims mismatch: %+v", got)
				}
			})
		}
	}
}
