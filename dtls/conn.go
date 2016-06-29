package dtls

import (
	"crypto/cipher"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type Conn struct {
	conn              net.Conn
	isClient          bool
	handshakeMutex    sync.Mutex
	handshakeErr      error
	config            *Config
	handshakeComplete bool
	peerCertificates  []*x509.Certificate
	verifiedChains    [][]*x509.Certificate
	serverName        string

	in, out halfConn
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
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	// TODO: check if handshake is complete

	if c.isClient {
		c.handshakeErr = c.clientHandshake()
	} else {
		c.handshakeErr = c.serverHandshake()
	}

	return ErrNotImplemented
}

func (c *Conn) serverHandshake() error {
	return ErrNotImplemented
}

func (c *Conn) sendAlert(err alert) error {
	return ErrNotImplemented
}

func (c *Conn) writeRecord(typ recordType, data []byte) (n int, err error) {

	b := c.out.newBlock()
	for len(data) > 0 {
		m := len(data)
		if m > maxPlaintext {
			m = maxPlaintext
		}
		explicitIVLen := 0
		explicitIVIsSeq := false

		var cbc cbcMode
		if c.out.version >= VersionTLS11 {
			var ok bool
			if cbc, ok = c.out.cipher.(cbcMode); ok {
				explicitIVLen = cbc.BlockSize()
			}
		}
		if explicitIVLen == 0 {
			if _, ok := c.out.cipher.(cipher.AEAD); ok {
				explicitIVLen = 8
				// The AES-GCM construction in TLS has an
				// explicit nonce so that the nonce can be
				// random. However, the nonce is only 8 bytes
				// which is too small for a secure, random
				// nonce. Therefore we use the sequence number
				// as the nonce.
				explicitIVIsSeq = true
			}
		}
		b.resize(recordHeaderLen + explicitIVLen + m)
		b.data[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			// Some TLS servers fail if the record version is
			// greater than TLS 1.0 for the initial ClientHello.
			vers = VersionTLS10
		}
		b.data[1] = byte(vers >> 8)
		b.data[2] = byte(vers)
		b.data[3] = byte(m >> 8)
		b.data[4] = byte(m)
		if explicitIVLen > 0 {
			explicitIV := b.data[recordHeaderLen : recordHeaderLen+explicitIVLen]
			if explicitIVIsSeq {
				copy(explicitIV, c.out.seq[:])
			} else {
				if _, err = io.ReadFull(c.config.rand(), explicitIV); err != nil {
					break
				}
			}
		}
		copy(b.data[recordHeaderLen+explicitIVLen:], data)
		c.out.encrypt(b, explicitIVLen)
		_, err = c.conn.Write(b.data)
		if err != nil {
			break
		}
		n += m
		data = data[m:]
	}
	c.out.freeBlock(b)

	if typ == recordTypeChangeCipherSpec {
		err = c.out.changeCipherSpec()
		if err != nil {
			// Cannot call sendAlert directly,
			// because we already hold c.out.Mutex.
			c.tmp[0] = alertLevelError
			c.tmp[1] = byte(err.(alert))
			c.writeRecord(recordTypeAlert, c.tmp[0:2])
			return n, c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
		}
	}
	return
}

func (c *Conn) write(data []byte) (int, error) {
	if c.buffering {
		c.sendBuf = append(c.sendBuf, data...)
		return len(data), nil
	}

	n, err := c.conn.Write(data)
	c.bytesSent += int64(n)
	return n, err
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

type halfConn struct {
	sync.Mutex

	err            error
	version        uint16
	cipher         interface{}
	mac            macFunction
	seq            [8]byte
	bfree          *block
	additionalData [13]byte

	nextCipher interface{}
	nextMac    macFunction

	inDigestBuf, outDigestBuf []byte
}

func (hc *halfConn) setErrorLocked(err error) error {
	hc.err = err
	return err
}

func (hc *halfConn) error() error {
	hc.Lock()
	err := hc.err
	hc.Unlock()
	return err
}

func (hc *halfConn) prepareCipherSpec(version uint16, cipher interface{}, mac macFunction) {
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
}

func (hc *halfConn) changeCipherSpec() error {
	if hc.nextCipher == nil {
		return alertInternalError
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

func (hc *halfConn) incSeq() {
	for i := 7; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}
	panic("dtls: sequence number wraparound")
}

// resetSeq resets the sequence number to zero.
func (hc *halfConn) resetSeq() {
	for i := range hc.seq {
		hc.seq[i] = 0
	}
}
