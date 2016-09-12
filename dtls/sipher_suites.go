package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"hash"
)

type keyAgreement interface {
	generateServerKeyExchange(*Config, *tls.Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error)
	processClientKeyExchange(*Config, *tls.Certificate, *clientKeyExchangeMsg, uint16) ([]byte, error)
	processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error
	generateClientKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
}

const (
	suiteECDHE = 1 << iota
	suiteECDSA
	suiteDTLS12
	suiteSHA384
	suiteDefaultOff
)

type cipherSuite struct {
	id     uint16
	keyLen int
	macLen int
	ivLen  int
	ka     func(version uint16) keyAgreement
	flags  int
	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(version uint16, macKey []byte) macFunction
	aead   func(key, fixedNonce []byte) cipher.AEAD
}

/*
SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_80 = {0x00, 0x01};
      SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_32 = {0x00, 0x02};
      SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_80      = {0x00, 0x05};
      SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_32      = {0x00, 0x06};
*/

var cipherSuites = []*cipherSuite{
	{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, suiteECDHE | suiteDTLS12, nil, nil, aeadAESGCM},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteDTLS12, nil, nil, aeadAESGCM},
	{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheRSAKA, suiteECDHE | suiteDTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteDTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, suiteECDHE | suiteDefaultOff, cipherRC4, macSHA1, nil},
	{tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteDefaultOff, cipherRC4, macSHA1, nil},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaKA, suiteDTLS12, nil, nil, aeadAESGCM},
	{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaKA, suiteDTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tls.TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, suiteDefaultOff, cipherRC4, macSHA1, nil},
	{tls.TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{tls.TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, suiteECDHE, cipher3DES, macSHA1, nil},
	{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, 0, cipher3DES, macSHA1, nil},
}

func cipherRC4(key, iv []byte, isRead bool) interface{} {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func cipher3DES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func macSHA1(version uint16, key []byte) macFunction {
	return dtls10MAC{hmac.New(sha1.New, key)}
}

type macFunction interface {
	Size() int
	MAC(digestBuf, seq, header, data []byte) []byte
}

type fixedNonceAEAD struct {
	sealNonce, openNonce []byte
	aead                 cipher.AEAD
}

func (f *fixedNonceAEAD) NonceSize() int { return 8 }
func (f *fixedNonceAEAD) Overhead() int  { return f.aead.Overhead() }

func (f *fixedNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.sealNonce[len(f.sealNonce)-8:], nonce)
	return f.aead.Seal(out, f.sealNonce, plaintext, additionalData)
}

func (f *fixedNonceAEAD) Open(out, nonce, plaintext, additionalData []byte) ([]byte, error) {
	copy(f.openNonce[len(f.openNonce)-8:], nonce)
	return f.aead.Open(out, f.openNonce, plaintext, additionalData)
}

func aeadAESGCM(key, fixedNonce []byte) cipher.AEAD {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	nonce1, nonce2 := make([]byte, 12), make([]byte, 12)
	copy(nonce1, fixedNonce)
	copy(nonce2, fixedNonce)

	return &fixedNonceAEAD{nonce1, nonce2, aead}
}

type dtls10MAC struct {
	h hash.Hash
}

func (s dtls10MAC) Size() int {
	return s.h.Size()
}

func (s dtls10MAC) MAC(digestBuf, seq, header, data []byte) []byte {
	s.h.Reset()
	s.h.Write(seq)
	s.h.Write(header)
	s.h.Write(data)
	return s.h.Sum(digestBuf[:0])
}

func rsaKA(version uint16) keyAgreement {
	return rsaKeyAgreement{}
}

func ecdheECDSAKA(version uint16) keyAgreement {
	return &ecdheKeyAgreement{
		sigType: signatureECDSA,
		version: version,
	}
}

func ecdheRSAKA(version uint16) keyAgreement {
	return &ecdheKeyAgreement{
		sigType: signatureRSA,
		version: version,
	}
}

func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			for _, suite := range cipherSuites {
				if suite.id == want {
					return suite
				}
			}
			return nil
		}
	}
	return nil
}
