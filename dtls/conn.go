package dtls

import (
	"net"
	"crypto/tls"
)

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	net.Conn
	config *tls.Config
	isClient bool
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return 0, ErrNotImplemented
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return 0, ErrNotImplemented
}
