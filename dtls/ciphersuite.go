package dtls

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/pkg/errors"
	"hash"
	"crypto/hmac"
	"log"
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rsa"
	"fmt"
	"io"
	"crypto/x509"
)

const (
	TLS_RSA_WITH_AES_128_CBC_SHA uint16 = 0x002f
)

var cipherSuites = []*cipherSuite{
	{TLS_RSA_WITH_AES_128_CBC_SHA, keyRSA, hashSHA1, 16, 20, 16, cipherAES, macSHA1},
}

const (
	keyRSA  uint8 = iota
	keyECDH
)

const (
	cipherTripleDES uint8 = iota
	cipherAES
)

const (
	macSHA1   uint8 = iota
	macSHA256
)

type cipherSuite struct {
	id     uint16
	typ    uint8
	hash   uint8
	key    int
	mac    int
	iv     int
	cipher uint8
	mach   uint8
}

func (c *cipherSuite) masterSecret(ver uint16, pre, crand, srand []byte) []byte {
	r := make([]byte, 48)
	c.prf(ver, r, pre, masterSecret, crand, srand)
	return r
}

func (c *cipherSuite) keyMaterial(ver uint16, master, crand, srand []byte) *keyMaterial {
	r := make([]byte, (c.key+c.mac+c.iv)<<1)
	c.prf(ver, r, master, crand, srand)
	k := &keyMaterial{}
	k.cmac, r = r[:c.mac], r[c.mac:]
	k.smac, r = r[:c.mac], r[c.mac:]
	k.ckey, r = r[:c.key], r[c.key:]
	k.skey, r = r[:c.key], r[c.key:]
	k.civ, k.siv = r[:c.iv], r[c.iv:]
	log.Printf("cmac %x", k.cmac)
	log.Printf("smac %x", k.smac)
	log.Printf("ckey %x", k.ckey)
	log.Printf("skey %x", k.skey)
	log.Printf("civ %x", k.civ)
	log.Printf("siv %x", k.siv)
	return k
}

func (c *cipherSuite) decrypter(key, iv []byte) cbcBlock {
	switch c.cipher {
	case cipherTripleDES:
		b, _ := des.NewTripleDESCipher(key)
		return cipher.NewCBCDecrypter(b, iv).(cbcBlock)
	case cipherAES:
		b, _ := aes.NewCipher(key)
		return cipher.NewCBCDecrypter(b, iv).(cbcBlock)
	}
	return nil
}

type cbcBlock interface {
	BlockSize() int
	CryptBlocks(dst, src []byte)
	SetIV(iv []byte)
}

func (c *cipherSuite) encrypter(key, iv []byte) cbcBlock {
	switch c.cipher {
	case cipherTripleDES:
		b, _ := des.NewTripleDESCipher(key)
		return cipher.NewCBCEncrypter(b, iv).(cbcBlock)
	case cipherAES:
		b, _ := aes.NewCipher(key)
		return cipher.NewCBCEncrypter(b, iv).(cbcBlock)
	}
	return nil
}

func (c *cipherSuite) macHash(key []byte) hash.Hash {
	switch c.mach {
	case macSHA1:
		return hmac.New(newConstantTimeSHA1, key)
	case macSHA256:
		return hmac.New(sha256.New, key)
	}
	return nil
}

func (c *cipherSuite) finishedHash(ver uint16, secret []byte, label, data []byte) []byte {
	r := make([]byte, 12)
	switch ver {
	case VersionDTLS10:
		m, h := md5.New(), sha1.New()
		m.Write(data)
		h.Write(data)
		s := make([]byte, 0, md5.Size+sha1.Size)
		c.prf(ver, r, secret, label, h.Sum(m.Sum(s[:0])))
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
	log.Printf("finished hash:\n%s", hex.Dump(r))
	return r
}

func (c *cipherSuite) prf(ver uint16, result, secret []byte, params ...[]byte) {
	switch ver {
	case VersionDTLS10:
		s1, s2 := secret[0:(len(secret)+1)/2], secret[len(secret)/2:]
		r := make([]byte, len(result))
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

var (
	masterSecret   = []byte("master secret")
	clientFinished = []byte("client finished")
	serverFinished = []byte("server finished")
	keyExpansion   = []byte("key expansion")
)

type keyMaterial struct {
	cmac, smac, ckey, skey, civ, siv []byte
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

type constantTimeHash struct {
	hash.Hash
	ConstantTimeSum func(b []byte) []byte
}

func (h *constantTimeHash) Sum(b []byte) []byte {
	return h.ConstantTimeSum(b)
}

func newConstantTimeSHA1() hash.Hash {
	h := sha1.New().(interface {
		hash.Hash
		ConstantTimeSum(b []byte) []byte
	})
	return &constantTimeHash{
		h,
		h.ConstantTimeSum,
	}
}
