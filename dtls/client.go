package dtls

import (
	"net"
	"crypto/rand"
	"log"
)

func NewClient(conn net.Conn, config *Config) (*Conn, error) {
	c := newConn(conn, config)

	h := &handshakeProtocol{Conn: c}
	if err := clientHandshake(h); err != nil {
		return nil, err
	}

	return c, nil
}

func clientHandshake(p *handshakeProtocol) error {
	r := make([]byte, 32)
	rand.Read(r)

	hello := &clientHello{
		ver:          VersionDTLS10,
		random:       r,
		cipherSuites: supportedCipherSuites,
		compMethods:  supportedCompression,
		extensions: &extensions{
			renegotiationSupported: true,
			srtpProtectionProfiles: srtpSupportedProtectionProfiles,
			extendedMasterSecret:   true,
			sessionTicket:          true,
			signatureAlgorithms:    supportedSignatureAlgorithms,
			supportedPoints:        supportedPointFormats,
			supportedCurves:        supportedCurves,
		},
	}
	p.send(&handshake{
		typ:     handshakeClientHello,
		message: hello,
	})
	var (
		verify *helloVerifyRequest
		req    *certificateRequest
		server *serverHello
		key    *serverKeyExchange
		cert   certificate
	)
	err := p.receive(func(h *handshake) (err error) {
		switch h.typ {
		case handshakeHelloVerifyRequest:
			verify, err = parseHelloVerifyRequest(h.raw)
			if err != nil {
				return err
			}
			if hello.cookie != nil {
				return errHandshakeSequence
			}
			hello.cookie = clone(verify.cookie)
			p.send(&handshake{
				typ:     handshakeClientHello,
				message: hello,
			})
		case handshakeServerHello:
			server, err = parseServerHello(clone(h.raw))
		case handshakeCertificate:
			cert, err = parseCertificate(clone(h.raw))
		case handshakeServerKeyExchange:
			key, err = parseServerKeyExchange(clone(h.raw))
		case handshakeCertificateRequest:
			req, err = parseCertificateRequest(clone(h.raw))
		case handshakeServerHelloDone:
			p.complete()
		default:
			return errHandshakeSequence
		}
		return
	})
	if err != nil {
		return err
	}

	p.alert()

	log.Printf("DONE")
	return nil
}
