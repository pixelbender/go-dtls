package dtls

import (
	"bytes"
	"io"
	"log"
	"net"
)

func NewClient(conn net.Conn, config *Config) (*Conn, error) {
	c := newConn(conn, config)
	h := &handshakeProtocol{Conn: c}
	if err := clientHandshake(h); err != nil {
		return nil, err
	}
	return c, nil
}

type session struct {
	ver uint16
}

func clientHandshake(p *handshakeProtocol) (err error) {
	hello := &clientHello{
		ver:          p.config.MaxVersion,
		random:       make([]byte, 32),
		cipherSuites: p.config.CipherSuites,
		compMethods:  supportedCompression,
		extensions: &extensions{
			renegotiationSupported: true,
			srtpProtectionProfiles: p.config.SRTPProtectionProfiles,
			extendedMasterSecret:   true,
			sessionTicket:          true,
			supportedPoints:        supportedPointFormats,
			supportedCurves:        supportedCurves,
		},
	}
	if _, err = io.ReadFull(p.config.Rand, hello.random); err != nil {
		p.tx.sendAlert(alertInternalError)
		return
	}
	if hello.ver == VersionDTLS12 {
		hello.signatureAlgorithms = supportedSignatureAlgorithms
	}

	var (
		server      *serverHello
		cert        *certificate
		cipherSuite *cipherSuite
	)

	p.send(&handshake{typ: handshakeClientHello, message: hello})
	err = p.receive(func(m *handshake) (done bool, err error) {
		switch m.typ {
		case handshakeHelloVerifyRequest:
			var req *helloVerifyRequest
			if req, err = parseHelloVerifyRequest(m.raw); err != nil {
				p.tx.sendAlert(alertDecodeError)
				return
			}
			// TODO: reset finished mac
			hello.cookie = clone(req.cookie)
			p.send(&handshake{typ: handshakeClientHello, message: hello})
		case handshakeServerHello:
			// TODO: write mac
			if server, err = parseServerHello(clone(m.raw)); err != nil {
				p.tx.sendAlert(alertDecodeError)
				return
			}
			cipherSuite = getCipherSuite(hello.cipherSuites, server.cipherSuite)
			// TODO: check compatibility
			if len(hello.sessionID) > 0 && bytes.Equal(hello.sessionID, server.sessionID) {
				// TODO: restore master secret and certs
			}
			log.Printf("%#v", server)
		case handshakeCertificate:
			// TODO: write mac
			if cert, err = parseCertificate(m.raw); err != nil {
				p.tx.sendAlert(alertBadCertificate)
				return
			}
			// TODO: check no certificates
			// TODO: validate certificate
			// TODO: verify peer certificate
			// TODO: check renegotiation
			log.Printf("%#v", cert.cert)
		case handshakeServerKeyExchange:
			// TODO: write mac
			var ex *serverKeyExchange
			if ex, err = parseServerKeyExchange(clone(m.raw)); err != nil {
				p.tx.sendAlert(alertUnexpectedMessage)
				return
			}

			log.Printf("%#v", ex)
		case handshakeServerHelloDone:
			done = true
		default:
			p.tx.sendAlert(alertUnexpectedMessage)
			err = errHandshakeSequence
		}
		return
	})
	if err != nil {
		return
	}

	log.Printf("Mess")
	return
}

//func clientServerCompatibility(client *clientHello, server *serverHello) error {
//	if server.compMethod != compNone {
//		return errors.New("dtls: server selected unsupported compression method")
//	}
//	ok := false
//	for _, it := range client.cipherSuites {
//		if it == server.cipherSuite {
//			ok = true
//			break
//		}
//	}
//	if !ok {
//		return errors.New("dtls: server selected unsupported compression method")
//	}
//}
