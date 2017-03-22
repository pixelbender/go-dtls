package dtls

import (
	"encoding/hex"
	"math/rand"
	"net"
	"testing"
)

func _TestClientWithOpenSSL(t *testing.T) {
	conn, err := net.Dial("udp", "127.0.0.1:4444")
	if err != nil {
		t.Fatal(err)
	}
	conn = &logConn{
		conn,
		t.Logf,
	}
	config := defaultConfig.Clone()
	config.InsecureSkipVerify = true
	c, err := NewClient(conn, config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
}

type lossConn struct {
	net.Conn
	rate float64
}

func (c *lossConn) Read(b []byte) (n int, err error) {
	for {
		n, err = c.Conn.Read(b)
		if rand.Float64() > c.rate {
			break
		}
	}
	return
}

type logConn struct {
	net.Conn
	Logf func(format string, args ...interface{})
}

func (c *logConn) Read(b []byte) (n int, err error) {
	if n, err = c.Conn.Read(b); err == nil {
		c.Logf("Read: %s", hex.Dump(b[:n]))
	}
	return
}

func (c *logConn) Write(b []byte) (n int, err error) {
	if n, err = c.Conn.Write(b); err == nil {
		c.Logf("Write: %s", hex.Dump(b))
	}
	return
}
