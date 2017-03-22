package dtls

import (
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var (
	errNotImplemented = errors.New("dtls: not implemented")
)

func Listen(network, laddr string, config *Config) (net.Listener, error) {
	addr, err := net.ResolveUDPAddr(network, laddr)
	if err != nil {
		return nil, err
	}
	// TODO: use self signed certificate if not specified
	c, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, err
	}
	return NewListener(c, config), nil
}

func NewListener(c *net.UDPConn, config *Config) *Listener {
	if config == nil {
		config = defaultConfig
	}
	l := &Listener{
		c:      c,
		config: config,
		accept: make(chan *conn, 16),
		conns:  make(map[string]*conn),
	}
	go l.serveConn()
	return l
}

type Listener struct {
	c      *net.UDPConn
	config *Config
	mu     sync.RWMutex
	accept chan *conn
	conns  map[string]*conn
}

func (l *Listener) Accept() (net.Conn, error) {
	// TODO: handle multiple goroutines
	c, ok := <-l.accept
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

func (l *Listener) Addr() net.Addr {
	return l.c.LocalAddr()
}

func (l *Listener) Close() error {
	// TODO: close acceptors and readers
	return l.c.Close()
}

func (l *Listener) serveConn() error {
	var (
		m, buf []byte
		v      [18]byte
	)
	for {
		if len(buf) < 4096 {
			buf = make([]byte, 1<<20)
		}
		n, addr, err := l.c.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		m, buf = buf[:n], buf[n:]
		v[0], v[1] = uint8(addr.Port>>8), uint8(addr.Port)
		id := v[:copy(v[2:], addr.IP)]
		l.mu.RLock()
		c := l.conns[string(id)]
		l.mu.RUnlock()
		if c == nil {
			l.mu.Lock()
			if c = l.conns[string(id)]; c == nil {
				c = newServerConn(l, addr, string(id))
				l.conns[string(id)] = c
			}
			l.mu.Unlock()
		}
		if err = c.serve(m); err != nil {
			c.Close()
		}
	}
}

func (l *Listener) closeConn(id string) {
	l.mu.Lock()
	delete(l.conns, id)
	l.mu.Unlock()
}

type conn struct {
	l     *Listener
	addr  *net.UDPAddr
	id    string
	serve func(b []byte) error
	in    chan []byte
}

func newServerConn(l *Listener, addr *net.UDPAddr, id string) *conn {
	return &conn{
		l:    l,
		addr: addr,
		id:   id,
		serve: func(b []byte) error {
			log.Printf("Read: %s", hex.Dump(b))
			return nil
		},
		in: make(chan []byte, 64),
	}
}

func (c *conn) SetDeadline(t time.Time) error {
	return errNotImplemented
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return errNotImplemented
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return errNotImplemented
}

func (c *conn) Read(p []byte) (n int, err error) {
	b, ok := <-c.in
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}

func (c *conn) Write(p []byte) (int, error) {
	return c.l.c.WriteToUDP(p, c.addr)
}

func (c *conn) LocalAddr() net.Addr {
	return c.l.Addr()
}

func (c *conn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *conn) Close() error {
	c.l.closeConn(c.id)
	return nil
}

type serverHandshake struct {
	handshakeTransport
	suite        *cipherSuite
	masterSecret []byte
}

func (c *serverHandshake) handshake() error {
	return nil
}
