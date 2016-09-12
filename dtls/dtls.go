package dtls

import (
	"errors"
	"net"
	"time"
)

var ErrNotImplemented = errors.New("dtls: not implemented")

// Listen creates a DTLS listener accepting connections on the
// given network address using net.ListenPacket.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || (len(config.Certificates) == 0 && config.GetCertificate == nil) {
		return nil, errors.New("dtls: neither Certificates nor GetCertificate set in Config")
	}
	l, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a DTLS handshake, returning the resulting
// DTLS connection.
// Dial interprets a nil configuration as equivalent to
// the zero configuration; see the documentation of Config
// for the defaults.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a DTLS handshake, returning the resulting DTLS connection. Any
// timeout or deadline given in the dialer apply to connection and DTLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of Config for the defaults.
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
	hostname, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = defaultConfig()
	}
	if config.ServerName == "" {
		c := *config
		c.ServerName = hostname
		config = &c
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

type timeoutError struct{}

func (timeoutError) Error() string   { return "dtls: timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
