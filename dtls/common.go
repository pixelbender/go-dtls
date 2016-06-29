package dtls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"sync"
	"time"
)

const (
	VersionDTLS10 = 0xfeff
	VersionDTLS12 = 0xfefd
)

const (
	minVersion = VersionDTLS10
	maxVersion = VersionDTLS12
)

type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-7
const (
	typeHelloRequest       uint8 = 0
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeNewSessionTicket   uint8 = 4
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
	typeCertificateStatus  uint8 = 22
	typeSupplementalData   uint8 = 23
)

const (
	compressionNone uint8 = 0
)

type CurveID uint16

// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
)

const (
	pointFormatUncompressed uint8 = 0
)

const (
	hashSHA1   uint8 = 2
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
)

const (
	signatureRSA   uint8 = 1
	signatureECDSA uint8 = 3
)

type signatureAndHash struct {
	hash, signature uint8
}

var supportedSignatureAlgorithms = []signatureAndHash{
	{hashSHA256, signatureRSA},
	{hashSHA256, signatureECDSA},
	{hashSHA384, signatureRSA},
	{hashSHA384, signatureECDSA},
	{hashSHA1, signatureRSA},
	{hashSHA1, signatureECDSA},
}

type ClientHelloInfo struct {
	CipherSuites []uint16
	ServerName   string
}

type Config struct {
	Rand                     io.Reader
	Time                     func() time.Time
	Certificates             []tls.Certificate
	NameToCertificate        map[string]*tls.Certificate
	GetCertificate           func(clientHello *ClientHelloInfo) (*tls.Certificate, error)
	RootCAs                  *x509.CertPool
	ServerName               string
	ClientCAs                *x509.CertPool
	InsecureSkipVerify       bool
	CipherSuites             []uint16
	PreferServerCipherSuites bool
	MinVersion               uint16
	MaxVersion               uint16
	CurvePreferences         []CurveID
}

func (c *Config) clone() *Config {
	return &Config{
		Rand:                     c.Rand,
		Time:                     c.Time,
		Certificates:             c.Certificates,
		NameToCertificate:        c.NameToCertificate,
		GetCertificate:           c.GetCertificate,
		RootCAs:                  c.RootCAs,
		ServerName:               c.ServerName,
		ClientCAs:                c.ClientCAs,
		InsecureSkipVerify:       c.InsecureSkipVerify,
		CipherSuites:             c.CipherSuites,
		PreferServerCipherSuites: c.PreferServerCipherSuites,
		MinVersion:               c.MinVersion,
		MaxVersion:               c.MaxVersion,
		CurvePreferences:         c.CurvePreferences,
	}
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

func (c *Config) minVersion() uint16 {
	if c == nil || c.MinVersion == 0 {
		return minVersion
	}
	return c.MinVersion
}

func (c *Config) maxVersion() uint16 {
	if c == nil || c.MaxVersion == 0 {
		return maxVersion
	}
	return c.MaxVersion
}

var defaultCurvePreferences = []CurveID{CurveP256, CurveP384, CurveP521}

func (c *Config) curvePreferences() []CurveID {
	if c == nil || len(c.CurvePreferences) == 0 {
		return defaultCurvePreferences
	}
	return c.CurvePreferences
}

func (c *Config) mutualVersion(vers uint16) (uint16, bool) {
	minVersion := c.minVersion()
	maxVersion := c.maxVersion()

	if vers < minVersion {
		return 0, false
	}
	if vers > maxVersion {
		vers = maxVersion
	}
	return vers, true
}

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}

var (
	once                   sync.Once
	varDefaultCipherSuites []uint16
)

func defaultCipherSuites() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuites
}

func initDefaultCipherSuites() {
	varDefaultCipherSuites = make([]uint16, 0, len(cipherSuites))
	for _, suite := range cipherSuites {
		if suite.flags&suiteDefaultOff != 0 {
			continue
		}
		varDefaultCipherSuites = append(varDefaultCipherSuites, suite.id)
	}
}

func isSupportedSignatureAndHash(sigHash signatureAndHash, sigHashes []signatureAndHash) bool {
	for _, s := range sigHashes {
		if s == sigHash {
			return true
		}
	}
	return false
}
