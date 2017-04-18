package dtls

import (
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"time"
	"hash"
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

	suite  *cipherSuite
	master []byte

	req   *helloVerifyRequest
	ch    *clientHello
	sh    *serverHello
	skey  *serverKeyExchange
	scert *certificate
	creq  *certificateRequest
	ckey  *clientKeyExchange
}

func (c *clientHandshake) handshake() (err error) {
	if c.ver == 0 {
		c.ver = c.config.MinVersion
	}
	c.ch = &clientHello{
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
	if _, err = io.ReadFull(c.config.getRand(), c.ch.random); err != nil {
		// TODO: send only if renegotiation
		c.sendAlert(alertInternalError)
		return err
	}
	if c.ch.ver == VersionDTLS12 {
		c.ch.signatureAlgorithms = supportedSignatureAlgorithms
	}

	c.prepare(&handshake{typ: handshakeClientHello, message: c.ch})
	if err = c.roundTrip(c.handleServerHello); err != nil {
		return err
	}

	if c.sh == nil || c.scert == nil || c.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return errHandshakeFailure
	}

	// TODO: check renegotiation
	// TODO: session resume

	if c.creq != nil {
		c.prepare(&handshake{typ: handshakeCertificate, message: &certificate{}})
		// TODO: write peer certificate chain
	}
	if c.ckey, err = c.clientKeyExchange(); err != nil {
		return err
	}

	c.prepare(&handshake{typ: handshakeClientKeyExchange, message: c.ckey})
	c.prepareRecord(&record{typ: recordChangeCipherSpec, raw: changeCipherSpec})
	c.epoch++

	c.sendFlight()
	c.clearFlight()

	c.establishKeys()
	c.config.writeKeyLog(c.ch.random, c.master)

	next := c.nextTransport()

	c.prepare(&handshake{typ: handshakeFinished, raw: c.suite.finishedHash(c.ver, c.master, clientFinished, c.log)})
	c.sendFlight()

	time.Sleep(1500 * time.Millisecond)
	c.sendAlert(alertCloseNotify)

	//return c.roundTrip(func(m *handshake) error {
	//	time.Sleep(50 * time.Millisecond)
	//	c.clearFlight()
	//	return nil
	//})

	return nil
}

func (c *clientHandshake) handleServerHello(h *handshake) (err error) {
	switch h.typ {
	case handshakeHelloVerifyRequest:
		if c.sh != nil {
			c.sendAlert(alertUnexpectedMessage)
			return errUnexpectedMessage
		}
		if c.req, err = parseHelloVerifyRequest(h.raw); err != nil {
			c.sendAlert(alertDecodeError)
			return err
		}
		if c.ver, err = c.config.getVersion(c.req.ver); err != nil {
			c.sendAlert(alertProtocolVersion)
			return err
		}
		c.ch.cookie = c.req.cookie
		c.reset()
		c.prepare(&handshake{typ: handshakeClientHello, message: c.ch})
		return nil
	case handshakeServerHello:
		if c.sh != nil {
			c.sendAlert(alertUnexpectedMessage)
			return errUnexpectedMessage
		}
		if c.sh, err = parseServerHello(h.raw); err != nil {
			c.sendAlert(alertDecodeError)
			return err
		}
		// TODO: Verify version from hello verify req
		if c.ver, err = c.config.getVersion(c.sh.ver); err != nil {
			c.sendAlert(alertProtocolVersion)
			return err
		}
		if _, err = c.config.getCompressionMethod(c.sh.compMethod); err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}
		if c.suite, err = c.config.getCipherSuite(c.sh.cipherSuite); err != nil {
			c.sendAlert(alertHandshakeFailure)
			return err
		}
		return nil
	case handshakeCertificate:
		if c.sh == nil {
			c.sendAlert(alertUnexpectedMessage)
			return errUnexpectedMessage
		}
		if c.scert, err = parseCertificate(h.raw); err != nil {
			c.sendAlert(alertDecodeError)
			return err
		}
		if err = c.config.verifyCertificate(c.scert.cert...); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
		return nil
	case handshakeServerKeyExchange:
		if c.sh == nil {
			c.sendAlert(alertUnexpectedMessage)
			return errUnexpectedMessage
		}
		if c.skey, err = parseServerKeyExchange(h.raw); err != nil {
			c.sendAlert(alertDecodeError)
			return err
		}
		return nil
	case handshakeCertificateRequest:
		if c.sh == nil {
			c.sendAlert(alertUnexpectedMessage)
			return errUnexpectedMessage
		}
		if c.creq, err = parseCertificateRequest(h.raw); err != nil {
			c.sendAlert(alertDecodeError)
			return err
		}
		return nil
	case handshakeServerHelloDone:
		if c.sh == nil {
			c.sendAlert(alertUnexpectedMessage)
			return errUnexpectedMessage
		}
		c.clearFlight()
		return nil
	default:
		c.sendAlert(alertUnexpectedMessage)
		return errUnexpectedMessage
	}
}

func (c *clientHandshake) clientKeyExchange() (*clientKeyExchange, error) {
	switch c.suite.typ {
	case keyRSA:
		cert := c.scert.cert[0]
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			c.sendAlert(alertUnsupportedCertificate)
			return nil, fmt.Errorf("dtls: unsupported type of certificate public key: %T", cert.PublicKey)
		}
		v := make([]byte, 48)
		v[0], v[1] = uint8(c.ch.ver>>8), uint8(c.ch.ver)
		if _, err := io.ReadFull(c.config.Rand, v[2:]); err != nil {
			c.sendAlert(alertInternalError)
			return nil, err
		}
		key, err := rsa.EncryptPKCS1v15(c.config.Rand, pub, v)
		if err != nil {
			c.sendAlert(alertInternalError)
			return nil, err
		}
		c.master = c.suite.masterSecret(c.ver, v, c.ch.random, c.sh.random)
		return &clientKeyExchange{typ: keyRSA, pub: key}, nil
	case keyECDH:
		// TODO: implement
		c.sendAlert(alertInternalError)
		return nil, errNotImplemented
	default:
		c.sendAlert(alertInternalError)
		return nil, errUnsupportedKeyExchangeAlgorithm
	}
}

type codec struct {
	enc struct {
		cipher cbcBlockMode
		hash   hash.Hash
	}
	dec struct {
		cipher cbcBlockMode
		hash   hash.Hash
	}
}

func (c *clientHandshake) establishKeys() error {
	k := c.suite.keyMaterial(c.ver, c.master, c.ch.random, c.sh.random)
	r := &codec{}
	r.dec.cipher = c.suite.decrypter(k.skey, k.siv)
	r.dec.hash = c.suite.macHash(k.smac)
	r.enc.cipher = c.suite.encrypter(k.ckey, k.civ)
	r.enc.hash = c.suite.macHash(k.cmac)
	c.codec = r
	return nil
}
