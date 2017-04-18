package tls

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"time"
	"fmt"
)

var defaultConfig = &Config{
	Rand: rand.Reader,
	Time: time.Now,
	CipherSuites: []uint16{
		TLS_RSA_WITH_AES_128_CBC_SHA,
	},
	InsecureSkipVerify: true,
	MinVersion: VersionTLS10,
	MaxVersion: VersionTLS12,
}

var (
	errUnsupportedProtocolVersion   = errors.New("tls: unsupported protocol version")
	errUnsupportedCipherSuite       = errors.New("tls: unsupported cipher suite")
	errUnsupportedCompressionMethod = errors.New("tls: unsupported compression method")
	errNoCertificate                = errors.New("tls: no certificate")
)

type Config struct {
	Rand               io.Reader
	Time               func() time.Time
	MTU                int
	RootCAs            *x509.CertPool
	ServerName         string
	CipherSuites       []uint16
	MinVersion         uint16
	MaxVersion         uint16
	InsecureSkipVerify bool
	Logf               func(format string, args ...interface{})
	KeyLogWriter       io.Writer
}

func (c *Config) Clone() *Config {
	if c != nil {
		r := *c
		return &r
	}
	return nil
}

func (c *Config) getRand() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *Config) getTime() time.Time {
	if c.Time != nil {
		return c.Time()
	}
	return time.Now()
}

func (c *Config) getRetransmissionTimeout() time.Time {
	if c.Time != nil {
		return c.Time()
	}
	return time.Now()
}

//
//func (c *Config) getVersion(ver uint16) (uint16, error) {
//	if c.MaxVersion == VersionDTLS10 && ver == VersionDTLS12 {
//		return 0, errUnsupportedProtocolVersion
//	}
//	return ver, nil
//}
/*
func (c *Config) getCipherSuite(suites ...uint16) (*cipherSuite, error) {
	for _, suite := range c.CipherSuites {
		for _, id := range suites {
			if suite != id {
				continue
			}
			for _, it := range cipherSuites {
				if it.id == id {
					return it, nil
				}
			}
		}
	}
	return nil, errUnsupportedCipherSuite
}

func (c *Config) getCompressionMethod(comp ...uint8) (uint8, error) {
	for _, id := range comp {
		if id == compNone {
			return compNone, nil
		}
	}
	return 0, errUnsupportedCompressionMethod
}
*/


func (c *Config) writeKeyLog(random, master []byte) error {
	if c.KeyLogWriter != nil {
		_, err := fmt.Fprintf(c.KeyLogWriter, "CLIENT_RANDOM %x %x\n", random, master)
		return err
	}
	return nil
}
