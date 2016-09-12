package dtls

import (
	"net"
)

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	net.Conn
	config   *Config
	isClient bool
	vers     uint16

	receiver receiver
	sender   sender
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
	c.receiver.inner = c.Conn
	if c.isClient {
		return clientHandshake(c)
	}
	return ErrNotImplemented
}

func (c *Conn) writeHandshakeRecord(typ uint8, data []byte) (int, error) {

	//var n int
	//vers := c.vers
	//if vers == 0 {
	//	vers = VersionDTLS10
	//}
	//
	//m := len(data)
	//
	//
	//b := make([]byte, 10000)
	//b[0] = byte(typ)
	//
	//be.PutUint16(b[1:], vers)
	//be.PutUint16(b[3:], 0) // epoch
	//be.PutUint64(b[5:], uint64(c.seq)) // len
	//be.PutUint16(b[11:], uint16(m)) // epoch
	//copy(b[recordHeaderLen:], data)
	//if _, err := c.write(b[:recordHeaderLen + m]); err != nil {
	//	return n, err
	//}
	//c.seq++
	//n += m
	//return n, nil
	return 0, nil
}
