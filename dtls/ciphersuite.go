package dtls

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/pkg/errors"
	"hash"
)

const (
	TLS_RSA_WITH_AES_128_CBC_SHA uint16 = 0x002f
)

var cipherSuites = []*cipherSuite{
	{TLS_RSA_WITH_AES_128_CBC_SHA, keyRSA, hashSHA1, 16, 20, 16},
	//, rsaKA, 0, cipherAES, macSHA1, nil},
}

type cipherSuite struct {
	id     uint16
	key    uint8
	hash   uint8
	keyLen int
	macLen int
	ivLen  int
	//ka     func(version uint16) keyAgreement
	//	// flags is a bitmask of the suite* values, above.
	//	flags  int
	//	cipher func(key, iv []byte, isRead bool) interface{}
	//	mac    func(version uint16, macKey []byte) macFunction
	//	aead   func(key, fixedNonce []byte) cipher.AEAD
}

func (c *cipherSuite) masterSecret(ver uint16, pre []byte, crand, srand []byte) []byte {
	r := make([]byte, 48)
	c.prf(ver, r, pre, masterSecret, crand, srand)
	return r
}

func (c *cipherSuite) finishedHash(ver uint16, secret []byte, label, data []byte) []byte {
	r := make([]byte, 12)
	switch ver {
	case VersionDTLS10:
		m, h := md5.New(), sha1.New()
		m.Write(data)
		h.Write(data)
		c.prf(ver, r, secret, label, h.Sum(m.Sum(nil)))
	case VersionDTLS12:
		var h hash.Hash
		switch c.hash {
		case hashSHA384:
			h = sha512.New384()
		case hashSHA512:
			h = sha512.New()
		default:
			h = sha256.New()
		}
		h.Write(data)
		c.prf(ver, r, secret, label, h.Sum(nil))
	}
	return r
}

func (c *cipherSuite) prf(ver uint16, result, secret []byte, params ...[]byte) {
	switch ver {
	case VersionDTLS10:
		s1, s2, r := secret[0:(len(secret)+1)/2], secret[len(secret)/2:], make([]byte, len(result))
		phash(md5.New, result, s1, params...)
		phash(sha1.New, r, s2, params...)
		for i, b := range r {
			result[i] ^= b
		}
	case VersionDTLS12:
		h := sha256.New
		switch c.hash {
		case hashSHA384:
			h = sha512.New384
		case hashSHA512:
			h = sha512.New
		}
		phash(h, result, secret, params...)
	}
}

var (
	errUnsupportedKeyExchangeAlgorithm = errors.New("dtls: unsupported key exchange algorithm")
)
