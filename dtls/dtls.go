package dtls

import (
	"errors"
	"net"
	"strings"
	"time"
)

var ErrNotImplemented = errors.New("dtls: not implemented")

func Client(conn net.Conn, config *Config) *Conn {
	return &Conn{conn: conn, config: config, isClient: true}
}

type listener struct {
	net.PacketConn
	config *Config
}

func (l *listener) Accept() (net.Conn, error) {
	return nil, ErrNotImplemented
}

func NewListener(inner net.PacketConn, config *Config) net.Listener {
	l := new(listener)
	l.PacketConn = inner
	l.config = config
	return l
}

func Listener(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || (len(config.Certificates) == 0 && config.GetCertificate == nil) {
		return nil, errors.New("dtls: neither Certificates nor GetCertificate set in Config")
	}
	l, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "dtls: timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	timeout := dialer.Timeout

	if !dialer.Deadline.IsZero() {
		deadlineTimeout := dialer.Deadline.Sub(time.Now())
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}

	var errChannel chan error

	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}

	if config.ServerName == "" {
		c := config.clone()
		c.ServerName = hostname
		config = c
	}

	conn := Client(rawConn, config)

	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()

		err = <-errChannel
	}

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

func Dial(network, addr string, config *Config) (net.Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}
