package dtls

import (
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"time"
)

func NewClient(conn net.Conn, config *Config) (*Conn, error) {
	c := newConn(conn, config)
	h := &clientHandshake{}
	h.transport = c.transport
	if err := h.handshake(); err != nil {
		return nil, err
	}
	return c, nil
}

type clientHandshake struct {
	handshakeTransport
	suite        *cipherSuite
	masterSecret []byte
}

func (c *clientHandshake) handshake() (err error) {
	ch := &clientHello{
		ver:          c.config.MaxVersion,
		random:       make([]byte, 32),
		cipherSuites: c.config.CipherSuites,
		compMethods:  supportedCompression,
		extensions: &extensions{
			renegotiationSupported: true,
			srtpProtectionProfiles: c.config.SRTPProtectionProfiles,
			extendedMasterSecret:   true,
			sessionTicket:          true,
			supportedPoints:        supportedPointFormats,
			supportedCurves:        supportedCurves,
		},
	}
	if _, err = io.ReadFull(c.config.getRand(), ch.random); err != nil {
		// TODO: send only if renegotiation handshake
		c.sendAlert(alertInternalError)
		return
	}
	if ch.ver == VersionDTLS12 {
		ch.signatureAlgorithms = supportedSignatureAlgorithms
	}
	var (
		req   *helloVerifyRequest
		sh    *serverHello
		skey  *serverKeyExchange
		scert *certificate
		creq  *certificateRequest
	)
	c.prepare(&handshake{typ: handshakeClientHello, message: ch})
	if err = c.roundTrip(func(m *handshake) (done bool, err error) {
		switch m.typ {
		case handshakeHelloVerifyRequest:
			if req, err = parseHelloVerifyRequest(m.raw); err != nil {
				break
			}
			ch.cookie = clone(req.cookie)
			c.reset()
			c.prepare(&handshake{typ: handshakeClientHello, message: ch})
		case handshakeServerHello:
			sh, err = parseServerHello(m.raw)
		case handshakeCertificate:
			scert, err = parseCertificate(m.raw)
		case handshakeServerKeyExchange:
			skey, err = parseServerKeyExchange(m.raw)
		case handshakeCertificateRequest:
			creq, err = parseCertificateRequest(m.raw)
		case handshakeServerHelloDone:
			done = true
		default:
			c.sendAlert(alertUnexpectedMessage)
			return false, errUnexpectedMessage
		}
		if err != nil {
			c.sendAlert(alertDecodeError)
		}
		return
	}); err != nil {
		return
	}

	if sh == nil || scert == nil {
		c.sendAlert(alertHandshakeFailure)
		return errUnexpectedMessage
	}

	//var (
	//	resume = len(ch.sessionID) > 0 && bytes.Equal(ch.sessionID, sh.sessionID)
	//)
	if c.ver, err = c.config.getVersion(sh.ver); err != nil {
		c.sendAlert(alertProtocolVersion)
		return
	}
	if c.suite, err = c.config.getCipherSuite(sh.cipherSuite); err != nil {
		c.sendAlert(alertHandshakeFailure)
		return
	}
	if _, err = c.config.getCompressionMethod(sh.compMethod); err != nil {
		c.sendAlert(alertUnexpectedMessage)
		return
	}
	if err = c.config.verifyCertificate(scert.cert...); err != nil {
		c.sendAlert(alertBadCertificate)
		return
	}
	// TODO: check renegotiation

	if creq != nil {
		c.prepare(&handshake{typ: handshakeCertificate, message: &certificate{}})
		// TODO: write peer certificate chain
	}

	switch c.suite.key {
	case keyRSA:
		var (
			cert    = scert.cert[0]
			pub, ok = cert.PublicKey.(*rsa.PublicKey)
			ckey    = &clientKeyExchange{typ: keyRSA}
		)
		if !ok {
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("dtls: unsupported type of certificate public key: %T", cert.PublicKey)
		}
		if ckey.pub, err = c.newMasterSecretRSA(ch, sh, pub); err != nil {
			c.sendAlert(alertInternalError)
			return
		}
		c.prepare(&handshake{typ: handshakeClientKeyExchange, message: ckey})
	case keyECDH:
		// TODO: implement
		c.sendAlert(alertInternalError)
		return fmt.Errorf("dtls: not implemented")
	default:
		c.sendAlert(alertInternalError)
		return errUnsupportedKeyExchangeAlgorithm
	}

	c.prepareRecord(&record{typ: recordChangeCipherSpec, raw: changeCipherSpec})

	//c.write(&handshake{typ: handshakeFinished, raw: c.finishedHash()})

	//c.tx.writeFlight(c.enc.raw, c.enc.rec)
	time.Sleep(time.Second)
	/*
		return c.flight(func(m *handshake) (done bool, err error) {
			return false, nil
		})*/
	return
}

func (c *clientHandshake) finishedHash() []byte {
	return c.suite.finishedHash(c.ver, c.masterSecret, clientFinished, c.log)
}

func (c *clientHandshake) newMasterSecretRSA(ch *clientHello, sh *serverHello, pub *rsa.PublicKey) ([]byte, error) {
	v := make([]byte, 48)
	v[0], v[1] = uint8(ch.ver>>8), uint8(ch.ver)
	if _, err := io.ReadFull(c.config.Rand, v[2:]); err != nil {
		return nil, err
	}
	c.masterSecret = c.suite.masterSecret(c.ver, v, ch.random, sh.random)
	return rsa.EncryptPKCS1v15(c.config.Rand, pub, v)
}
