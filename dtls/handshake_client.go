package dtls

import (
	"errors"
	"io"
	"net"
	"strings"
)

func (c *Conn) clientHandshake() error {
	if c.config == nil {
		c.config = defaultConfig()
	}

	if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify {
		return errors.New("dtls: either ServerName or InsecureSkipVerify must be specified in the dtls.Config")
	}

	// TODO: check next proto

	sni := c.config.ServerName
	if net.ParseIP(sni) != nil {
		sni = ""
	}

	hello := &clientHelloMsg{
		vers:               c.config.maxVersion(),
		compressionMethods: []uint8{compressionNone},
		random:             make([]byte, 32),
		ocspStapling:       true,
		scts:               true,
		serverName:         sni,
		supportedCurves:    c.config.curvePreferences(),
		supportedPoints:    []uint8{pointFormatUncompressed},
		//nextProtoNeg:        len(c.config.NextProtos) > 0,
		secureRenegotiation: true,
		//alpnProtocols:       c.config.NextProtos,
	}

	possibleCipherSuites := c.config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		for _, suite := range cipherSuites {
			if suite.id != suiteId {
				continue
			}
			if hello.vers < VersionDTLS12 && suite.flags&suiteDTLS12 != 0 {
				continue
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			continue NextCipherSuite
		}
	}

	_, err := io.ReadFull(c.config.rand(), hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("dtls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionDTLS12 {
		hello.signatureAndHashes = supportedSignatureAlgorithms
	}

	// TODO: session tickets

	c.writeRecord(recordTypeHandshake, hello.marshal())

	// TODO: wait for response

	return ErrNotImplemented
}

func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
