package tls

import (
	"github.com/pkg/errors"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"crypto/hmac"
	"crypto/des"
	"crypto/cipher"
	"crypto/aes"
)

const (
	TLS_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
	TLS_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0x003c
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
)

const (
	tls10 = VersionTLS10
	tls11 = VersionTLS12
	tls12 = VersionTLS12
)

var cipherSuites = []*cipherSuite{
	{TLS_RSA_WITH_AES_128_CBC_SHA, tls10, tls12, keyExchangeRSA, digestSHA, cipherAES128CBC, macSHA1},
	{TLS_RSA_WITH_AES_128_CBC_SHA256, tls12, tls12, keyExchangeRSA, digestSHA256, cipherAES128CBC, macSHA256},

	//{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 0, 2, keyExchangeRSA, cipherAES, hashSHA1, 32, 20, 16},
	//	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 2, 2, keyExchangeRSA, cipherAES, hashSHA1, 16, 0, 4},
	//	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 0, 2, keyExchangeRSA, cipherTripleDES, hashSHA1, 24, 20, 8},
} // SHA1, MD5, SHA256, SHA384, SHA512, SHA224

type cipherSuite struct {
	id          uint16
	min, max    uint16
	keyExchange func() keyExchange
	digest      func(ver uint16) func() hash.Hash
	blockCipher *blockCipher
	macHash     *macHash
}

type blockCipher struct {
	size      int
	ext       int
	block     func(key []byte) (cipher.Block, error)
	blockMode func(b cipher.Block, ext []byte, write bool) cbcBlock
}

func (c *blockCipher) encrypter(key, ext []byte) cbcBlock {
	b, _ := c.block(key)
	return c.blockMode(b, ext, true)
}

func (c *blockCipher) decrypter(key, ext []byte) cbcBlock {
	b, _ := c.block(key)
	return c.blockMode(b, ext, false)
}

var (
	cipherAES128CBC = &blockCipher{16, 16, aes.NewCipher, blockModeCBC }
	cipherAES256CBC = &blockCipher{32, 16, aes.NewCipher, blockModeCBC }
	cipher3DES      = &blockCipher{24, 8, des.NewTripleDESCipher, blockModeCBC }
)

func blockModeCBC(b cipher.Block, ext []byte, write bool) cbcBlock {
	if write {
		return cipher.NewCBCEncrypter(b, ext).(cbcBlock)
	}
	return cipher.NewCBCDecrypter(b, ext).(cbcBlock)
}

func digestSHA(ver uint16) func() hash.Hash {
	if ver < VersionTLS12 {
		return sha1.New
	}
	return sha256.New
}

func digestSHA256(ver uint16) func() hash.Hash {
	return sha256.New
}

func digestSHA384(ver uint16) func() hash.Hash {
	return sha512.New384
}

type macHash struct {
	size int
	hash func() hash.Hash
}

var (
	macSHA1 = &macHash{
		sha1.Size,
		func() hash.Hash {
			h := sha1.New().(interface {
				hash.Hash
				ConstantTimeSum(b []byte) []byte
			})
			return &constantTimeHash{
				h,
				h.ConstantTimeSum,
			}
		},
	}
	macSHA256 = &macHash{
		sha256.Size,
		sha256.New,
	}
)

type cbcBlock interface {
	BlockSize() int
	CryptBlocks(dst, src []byte)
	SetIV(iv []byte)
}

func (c *cipherSuite) masterSecret(ver uint16, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	r := make([]byte, 48)
	c.prf(ver, r, preMasterSecret, masterSecret, clientRandom, serverRandom)
	return r
}

func (c *cipherSuite) keyMaterial(ver uint16, masterSecret, clientRandom, serverRandom []byte) *keyMaterial {
	mac, key, ext := 0, c.blockCipher.size, c.blockCipher.ext
	if c.macHash != nil {
		mac = c.macHash.size
	}
	r := make([]byte, (mac+key+ext)<<1)
	c.prf(ver, r, masterSecret, keyExpansion, serverRandom, clientRandom)
	k := &keyMaterial{}
	if mac > 0 {
		k.cmac, r = r[:mac], r[mac:]
		k.smac, r = r[:mac], r[mac:]
	}
	k.ckey, r = r[:key], r[key:]
	k.skey, r = r[:key], r[key:]
	k.civ, k.siv = r[:ext], r[ext:]
	return k
}

func (c *cipherSuite) clientCipher(key *keyMaterial) *cipherSpec {
	return &cipherSpec{
		c.blockCipher.encrypter(key.ckey, key.civ),
		hmac.New(c.macHash.hash, key.cmac),
		c.blockCipher.decrypter(key.skey, key.siv),
		hmac.New(c.macHash.hash, key.smac),
	}
}

type keyMaterial struct {
	cmac, smac, ckey, skey, civ, siv []byte
}

func (c *cipherSuite) finishedHash(ver uint16, masterSecret []byte, label []byte, messages ... []byte) []byte {
	r := make([]byte, 12)
	switch ver {
	case VersionTLS10, VersionTLS11:
		m, h := md5.New(), sha1.New()
		for _, p := range messages {
			m.Write(p)
			h.Write(p)
		}
		s := make([]byte, 0, md5.Size+sha1.Size)
		c.prf(ver, r, masterSecret, label, h.Sum(m.Sum(s[:0])))
	default:
		h := c.digest(ver)()
		for _, p := range messages {
			h.Write(p)
		}
		c.prf(ver, r, masterSecret, label, h.Sum(nil))
	}
	return r
}

func (c *cipherSuite) prf(ver uint16, result, secret []byte, params ...[]byte) {
	switch ver {
	case VersionTLS10, VersionTLS11:
		r := make([]byte, len(result))
		phash(md5.New, result, secret[:(len(secret)+1)/2], params...)
		phash(sha1.New, r, secret[len(secret)/2:], params...)
		for i, b := range r {
			result[i] ^= b
		}
	default:
		phash(c.digest(ver), result, secret, params...)
	}
}

func phash(hash func() hash.Hash, result, secret []byte, params ...[]byte) {
	h := hmac.New(hash, secret)
	for _, p := range params {
		h.Write(p)
	}
	a := h.Sum(nil)
	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		for _, p := range params {
			h.Write(p)
		}
		b := h.Sum(nil)
		t := len(b)
		if j+t > len(result) {
			t = len(result) - j
		}
		copy(result[j:j+t], b)
		j += t
		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

func selectCipherSuite(want []uint16, suites ...uint16) (*cipherSuite, error) {
	for _, v := range want {
		for _, id := range suites {
			if id != v {
				continue
			}
			for _, suite := range cipherSuites {
				if suite.id == id {
					return suite, nil
				}
			}
		}
	}
	return nil, errUnsupportedCipherSuites
}

var (
	masterSecret   = []byte("master secret")
	clientFinished = []byte("client finished")
	serverFinished = []byte("server finished")
	keyExpansion   = []byte("key expansion")
)

var (
	errUnsupportedCipherSuites = errors.New("tls: unsupported cipher suite")
)

type constantTimeHash struct {
	hash.Hash
	ConstantTimeSum func(b []byte) []byte
}

func (h *constantTimeHash) Sum(b []byte) []byte {
	return h.ConstantTimeSum(b)
}
