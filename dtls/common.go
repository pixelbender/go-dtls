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

const (
	compressionNone uint8 = 0
)

const (
	extensionServerName          uint16 = 0
	extensionStatusRequest       uint16 = 5
	extensionSupportedCurves     uint16 = 10
	extensionSupportedPoints     uint16 = 11
	extensionSignatureAlgorithms uint16 = 13
	extensionALPN                uint16 = 16
	extensionSCT                 uint16 = 18 // https://tools.ietf.org/html/rfc6962#section-6
	extensionSessionTicket       uint16 = 35
	extensionNextProtoNeg        uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo   uint16 = 0xff01
)

// http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
const (
	extServerName           uint16 = 0     // RFC 6066
	extExtendedMasterSecret uint16 = 23    // RFC 7627
	extSessionTicket        uint16 = 35    // RFC 4507
	extSignatureAlgorithms  uint16 = 13    // RFC 5246
	extSupportedPoints      uint16 = 11    // RFC 4492
	extSupportedGroups      uint16 = 10    // RFC 7919
	extRenegotiationInfo    uint16 = 65281 // RFC 5746
)

const (
	scsvRenegotiation uint16 = 0x00ff
)

type CurveID uint16

// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign    = 1 // A certificate containing an RSA key
	certTypeDSSSign    = 2 // A certificate containing a DSA key
	certTypeRSAFixedDH = 3 // A certificate containing a static DH key
	certTypeDSSFixedDH = 4 // A certificate containing a static DH key

	// See RFC 4492 sections 3 and 5.5.
	certTypeECDSASign      = 64 // A certificate containing an ECDSA-capable public key, signed with ECDSA.
	certTypeRSAFixedECDH   = 65 // A certificate containing an ECDH-capable public key, signed with RSA.
	certTypeECDSAFixedECDH = 66 // A certificate containing an ECDH-capable public key, signed with ECDSA.

	// Rest of these are reserved by the TLS spec
)

const (
	hashSHA1   uint8 = 2
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
	hashSHA512 uint8 = 6
)

const (
	signatureRSA   uint8 = 1
	signatureECDSA uint8 = 3
)

type signatureAlgorithm struct {
	hash, sign uint8
}

var supportedSignatureAlgorithms = []signatureAlgorithm{
	{hashSHA512, signatureRSA},
	{hashSHA512, signatureECDSA},
	{hashSHA256, signatureRSA},
	{hashSHA256, signatureECDSA},
	{hashSHA384, signatureRSA},
	{hashSHA384, signatureECDSA},
	{hashSHA1, signatureRSA},
	{hashSHA1, signatureECDSA},
}

const (
	curveSecp256r1 uint16 = 23
	curveSecp384r1 uint16 = 24
	curveSecp512r1 uint16 = 24
)

var supportedEllipticCurves = []uint16{curveSecp256r1, curveSecp384r1, curveSecp512r1}

type ClientHelloInfo struct {
	CipherSuites []uint16
	ServerName   string
}

const (
	pointUncompressed uint8 = 0
)

var supportedPointFormats = []uint8{pointUncompressed}

type Config struct {
	MTU                      int
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
	SessionTicketsDisabled   bool
	MinVersion               uint16
	MaxVersion               uint16
	CurvePreferences         []CurveID

	Extensions map[uint16][]byte
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

func (c *Config) mtu() (r int) {
	if r = c.MTU; r == 0 {
		return 1500
	}
	return
}

func (c *Config) rand() (r io.Reader) {
	if r = c.Rand; r == nil {
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

func isSupportedSignatureAndHash(sigHash signatureAlgorithm, sigHashes []signatureAlgorithm) bool {
	for _, s := range sigHashes {
		if s == sigHash {
			return true
		}
	}
	return false
}
