package dtls

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"time"
)

const (
	VersionDTLS10 = 0xfeff
	VersionDTLS12 = 0xfefd
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
	CipherSuites             []uint16
	PreferServerCipherSuites bool
	MinVersion               uint16
	MaxVersion               uint16
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
		CipherSuites:             c.CipherSuites,
		PreferServerCipherSuites: c.PreferServerCipherSuites,
		MinVersion:               c.MinVersion,
		MaxVersion:               c.MaxVersion,
	}
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}
