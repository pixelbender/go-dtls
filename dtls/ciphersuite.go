package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"
)

const (
	TLS_RSA_WITH_AES_128_CBC_SHA uint16 = 0x002f
)

var cipherSuites = []*cipherSuite{
//{TLS_RSA_WITH_AES_128_CBC_SHA, sha512.New384, 16, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
}

func getCipherSuite(pref []uint16, id uint16) *cipherSuite {
	for _, it := range pref {
		if it != id {
			continue
		}
		for _, cs := range cipherSuites {
			if cs.id == id {
				return cs
			}
		}
	}
	return nil
}

type cipherSuite struct {
	id   uint16
	hash func() hash.Hash
	//	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	ka     func(version uint16) keyAgreement
	//	// flags is a bitmask of the suite* values, above.
	//	flags  int
	//	cipher func(key, iv []byte, isRead bool) interface{}
	//	mac    func(version uint16, macKey []byte) macFunction
	//	aead   func(key, fixedNonce []byte) cipher.AEAD
}

func cipherAES(key, iv []byte, read bool) interface{} {
	block, _ := aes.NewCipher(key)
	if read {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

//func rsaKA(version uint16) keyAgreement {
//	return rsaKeyAgreement{}
//}
