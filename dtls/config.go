package dtls

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"time"
	"fmt"
)

var defaultConfig = &Config{
	Rand:                     rand.Reader,
	Time:                     time.Now,
	MTU:                      1400,
	MinRetransmissionTimeout: 100 * time.Millisecond,
	MaxRetransmissionTimeout: time.Second,
	ReadTimeout:              5 * time.Second,
	CipherSuites: []uint16{
		TLS_RSA_WITH_AES_128_CBC_SHA,
		//tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		//tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		//tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		//tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		//tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		//tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		//tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		//tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		//tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		//tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		//tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		//tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		//tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		//tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	},
	MinVersion: VersionDTLS10,
	MaxVersion: VersionDTLS10,
}

var (
	errUnsupportedProtocolVersion   = errors.New("dtls: unsupported protocol version")
	errUnsupportedCipherSuite       = errors.New("dtls: unsupported cipher suite")
	errUnsupportedCompressionMethod = errors.New("dtls: unsupported compression method")
	errNoCertificate                = errors.New("dtls: no certificate")
)

type Config struct {
	Rand                     io.Reader
	Time                     func() time.Time
	MTU                      int
	MinRetransmissionTimeout time.Duration
	MaxRetransmissionTimeout time.Duration
	ReadTimeout              time.Duration
	RootCAs                  *x509.CertPool
	ServerName               string
	CipherSuites             []uint16
	SRTPProtectionProfiles   []uint16
	MinVersion               uint16
	MaxVersion               uint16
	InsecureSkipVerify       bool
	Logf                     func(format string, args ...interface{})
	KeyLogWriter             io.Writer
}

func (c *Config) Clone() *Config {
	if c != nil {
		r := *c
		return &r
	}
	return nil
}

func (c *Config) getMTU() int {
	if c.MTU > 25 {
		return c.MTU
	}
	return 1400
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

func (c *Config) getVersion(ver uint16) (uint16, error) {
	if c.MaxVersion == VersionDTLS10 && ver == VersionDTLS12 {
		return 0, errUnsupportedProtocolVersion
	}
	return ver, nil
}

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

func (c *Config) verifyCertificate(certs ...*x509.Certificate) error {
	if len(certs) == 0 {
		return errNoCertificate
	}
	cert := certs[0]
	if !c.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.RootCAs,
			CurrentTime:   c.Time(),
			DNSName:       c.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, it := range certs[1:] {
			opts.Intermediates.AddCert(it)
		}
		_, err := cert.Verify(opts)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) writeKeyLog(random, master []byte) error {
	if c.KeyLogWriter != nil {
		_, err := fmt.Fprintf(c.KeyLogWriter, "CLIENT_RANDOM %x %x\n", random, master)
		return err
	}
	return nil
}
