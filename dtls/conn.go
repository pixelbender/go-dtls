package dtls

import (
	"net"
	"crypto/tls"
)

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	net.Conn
	config   *tls.Config
	isClient bool
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return 0, ErrNotImplemented
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return 0, ErrNotImplemented
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
// Most uses of this package need not call Handshake
// explicitly: the first Read or Write will call it automatically.
func (c *Conn) Handshake() error {
	if c.isClient {
		return c.clientHandshake()
	}
	return ErrNotImplemented
}

