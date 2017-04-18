package tls

import (
	"time"
	"io"
	"net"
	"fmt"
	"crypto/x509"
)

func Dial(network, address string, config *Config) (*Conn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	c, err := newClient(conn, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func newClient(conn net.Conn, config *Config) (*Conn, error) {
	if config == nil {
		config = defaultConfig
	}
	tr, err := newTransport(conn, config)
	if err != nil {
		return nil, err
	}
	handshake := &clientHandshake{config}
	next, err := handshake.Do(tr)
	if err != nil {
		return nil, err
	}
	return newConn(next, config), nil
}

type clientHandshake struct {
	*Config
}

func (c *clientHandshake) Do(tr transport) (next transport, err error) {
	// TODO: session tickets
	// TODO: next protos
	// TODO: renegotiation

	clientHello := &clientHello{
		ver:                c.MaxVersion,
		random:             make([]byte, 32),
		cipherSuites:       c.CipherSuites,
		compressionMethods: supportedCompressionMethods,
		extensions: extensions{
			renegotiationSupported: true,
			extendedMasterSecret:   true,
			sessionTicket:          true,
			supportedPoints:        supportedPointFormats,
			supportedCurves:        supportedCurves,
		},
	}
	if _, err = io.ReadFull(c.Rand, clientHello.random); err != nil {
		// TODO: send only if renegotiation
		tr.SendAlert(alertInternalError)
		return
	}
	if clientHello.ver == VersionTLS12 {
		clientHello.signatureAlgorithms = supportedSignatureAlgorithms
	}
	if err = tr.WriteHandshake(clientHello); err != nil {
		return
	}
	serverHello := &serverHello{}
	if _, err = tr.ReadHandshake(serverHello); err != nil {
		return
	}
	// TODO: check version...
	if serverHello.ver < c.MinVersion {
		tr.SendAlert(alertProtocolVersion)
		return nil, &errUnsupportedProtocol{serverHello.ver, c.MinVersion}
	}
	tr.SetVersion(serverHello.ver)
	cipherSuite, err := selectCipherSuite(clientHello.cipherSuites, serverHello.cipherSuite)
	if err != nil {
		tr.SendAlert(alertHandshakeFailure)
		return
	}
	// TODO: check resume...

	cert := &certificate{}
	if _, err = tr.ReadHandshake(cert); err != nil {
		return
	}
	if err = c.verifyCertificate(cert.cert); err != nil {
		tr.SendAlert(alertBadCertificate)
		return
	}

	//TODO: ocsp stapling

	/*
	serverKey := &serverKeyExchange{}
	if _, err = tr.ReadHandshake(cert); err != nil {
		return
	}
	if err = c.verifyCertificate(cert.cert); err != nil {
		tr.SendAlert(alertBadCertificate)
		return
	}
	*/
	certReq, serverDone := &certificateRequest{}, &serverHelloDone{}
	typ, err := tr.ReadHandshake(certReq, serverDone)
	if err != nil {
		return
	}
	if typ == handshakeCertificateRequest {
		// TODO: send client certs
		cert := &certificate{}
		if err = tr.WriteHandshake(cert); err != nil {
			return
		}
		if _, err = tr.ReadHandshake(serverDone); err != nil {
			return
		}
	}

	keyExchange := cipherSuite.keyExchange()
	preMasterSecret, clienKey, err := keyExchange.newClientKey(c.Config, clientHello, cert.cert[0])
	if err != nil {
		tr.SendAlert(alertInternalError)
		return
	}

	if err = tr.WriteHandshake(clienKey); err != nil {
		return
	}
	masterSecret := cipherSuite.masterSecret(serverHello.ver, preMasterSecret, clientHello.random, serverHello.random)
	if err = tr.WriteRecord(recordChangeCipherSpec, changeCipherSpec); err != nil {
		return
	}

	key := cipherSuite.keyMaterial(serverHello.ver, masterSecret, clientHello.random, serverHello.random)

	next = tr.Next(cipherSuite.clientCipher(key))

	verifyData := cipherSuite.finishedHash(serverHello.ver, masterSecret, clientFinished, tr.Handshake(), next.Handshake())
	if err = next.WriteHandshake(&finished{verifyData}); err != nil {
		return
	}

	/*	k := cipherSuite.keyMaterial(serverHello.ver, master, clientHello.random, serverHello.random)
		cipherSpec := &cipherSpec{
			cipherSuite.encrypter(k.ckey, k.civ),
			cipherSuite.macHash(k.cmac),
			cipherSuite.decrypter(k.skey, k.siv),
			cipherSuite.macHash(k.smac),
		}

		next = tr.Next(cipherSpec)



		serverFinished := &finished{}
		if _, err = tr.ReadHandshake(serverFinished); err != nil {
			return
		}

		log.Printf("YEAH >> %v %v", serverHello, cipherSuite)*/
	time.Sleep(time.Second)
	tr.SendAlert(alertCloseNotify)
	return
}

func (c *clientHandshake) verifyCertificate(cert []*x509.Certificate) error {
	if len(cert) == 0 {
		return errNoCertificate
	}
	v := cert[0]
	if !c.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.RootCAs,
			CurrentTime:   c.Time(),
			DNSName:       c.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, it := range cert[1:] {
			opts.Intermediates.AddCert(it)
		}
		_, err := v.Verify(opts)
		if err != nil {
			return err
		}
	}
	// TODO: verify peer certificate
	return nil
}

type errUnsupportedProtocol struct {
	ver, min uint16
}

func (e errUnsupportedProtocol) String() string {
	return fmt.Sprintf("tls: unsupported protocol version %x, minimal required %x", e.ver, e.min)
}

func (e errUnsupportedProtocol) Error() string {
	return e.String()
}
