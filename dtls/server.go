package dtls

import (
	"net"
	"sync"
)

// Server returns a new DTLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(conn net.Conn, config *Config) *Conn {
	return &Conn{Conn: conn, config: config}
}

// A listener implements a network listener (net.Listener) for DTLS connections.
type listener struct {
	net.PacketConn
	config *Config
	//srv map[string]*Server
	mu sync.RWMutex
}

// NewListener creates a Listener which accepts connections from an inner
// PacketConn and wraps each connection with Server.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func NewListener(inner net.PacketConn, config *Config) net.Listener {
	l := new(listener)
	l.PacketConn = inner
	l.config = config
	//l.clients = make(map[string]*Conn)
	return l
}

// Accept waits for and returns the next incoming DTLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c := l.PacketConn.(*net.UDPConn)
	if c == nil {
		return nil, ErrNotImplemented
	}
	//b := make([]byte, maxPacketSize)
	//for {
	//	n, addr, err := c.ReadMsgUDP()
	//
	//
	//	k := string(append(addr.IP, byte(addr.Port >> 8), byte(addr.Port)))
	//
	//}
	//for {
	//n, addr, err := l.conn.ReadFrom(b)
	//if err != nil {
	//	return err
	//}
	//
	//b[:n]
	//}
	//return Server(c, l.config), nil
	return nil, ErrNotImplemented
}

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return l.LocalAddr()
}
