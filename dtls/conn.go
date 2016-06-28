package dtls

import (
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"
)

type Conn struct {
	conn              net.Conn
	isClient          bool
	handshakeMutex    sync.Mutex
	config            *Config
	handshakeComplete bool
	peerCertificates  []*x509.Certificate
	verifiedChains    [][]*x509.Certificate
	serverName        string
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return 0, ErrNotImplemented
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return 0, ErrNotImplemented
}

func (c *Conn) Close() error {
	// TODO: check active calls

	var alertErr error

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if c.handshakeComplete {

		// TODO: send alert
		alertErr = ErrNotImplemented
	}

	if err := c.conn.Close(); err != nil {
		return err
	}
	return alertErr
}

func (c *Conn) Handshake() error {
	return ErrNotImplemented
}

func (c *Conn) VerifyHostname(host string) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.isClient {
		return errors.New("dtls: VerifyHostname called on DTLS server connection")
	}
	if !c.handshakeComplete {
		return errors.New("dtls: handshake has not yet been performed")
	}
	if len(c.verifiedChains) == 0 {
		return errors.New("dtls: handshake did not verify certificate chain")
	}
	return c.peerCertificates[0].VerifyHostname(host)
}
