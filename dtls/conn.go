package dtls

import (
	"net"
)

type Conn struct {
	*transport
}

func newConn(c net.Conn, config *Config) *Conn {
	if config == nil {
		config = defaultConfig
	}
	conn := &Conn{
		&transport{Conn: c, config: config},
	}
	return conn
}

func (c *Conn) Close() error {
	// TODO: send alert only if handshake done
	c.sendAlert(alertCloseNotify)
	return c.Conn.Close()
}
