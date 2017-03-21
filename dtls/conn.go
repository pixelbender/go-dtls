package dtls

import (
	"io"
	"net"
)

type Conn struct {
	net.Conn
	config *Config
	rx     receiver
	tx     transmitter
}

func newConn(c net.Conn, config *Config) *Conn {
	if config == nil {
		config = DefaultConfig
	}
	return &Conn{
		c,
		config,
		receiver{r: c},
		transmitter{w: c, mtu: config.MTU},
	}
}

func (c *Conn) newHandshake() *handshakeProtocol {
	return &handshakeProtocol{
		Conn: c,
		enc: handshakeEncoder{
			mtu: c.config.MTU,
			seq: 0,
		},
		dec: handshakeDecoder{
			seq: 0,
		},
	}
}

func (c *Conn) sendAlert(a uint8) error {
	return c.tx.write(&record{
		typ: recordAlert,
		ver: VersionDTLS10,
		raw: []byte{levelError, a},
	})
}

func (c *Conn) Close() error {
	// TODO: send alert only if handshake done
	c.sendAlert(alertCloseNotify)
	return c.Conn.Close()
}

type receiver struct {
	r     io.Reader
	epoch uint16
	seq   int64
	mask  int64
	buf   []byte
	raw   []byte
}

func (rx *receiver) read() (r *record, err error) {
	if rx.buf == nil {
		rx.buf = make([]byte, 4096)
	}
	for {
		if len(rx.raw) > 0 {
			r, rx.raw, err = parseRecord(rx.raw)
			if err == nil && rx.check(r) {
				return r, nil
			}
		}
		n, err := rx.r.Read(rx.buf)
		if err != nil {
			return nil, err
		}
		rx.raw = rx.buf[:n]
	}
}

func (rx *receiver) check(r *record) bool {
	if r.epoch != rx.epoch {
		return false
	}
	d := r.seq - rx.seq
	if d > 0 {
		if d < 64 {
			rx.mask = (rx.mask << uint(d)) | 1
		} else {
			rx.mask = 1
		}
		rx.seq = r.seq
		return true
	}
	if d = -d; d >= 64 {
		return false
	}
	if b := int64(1) << uint(d); rx.mask&b == 0 {
		rx.mask |= b
		return true
	}
	return false
}

type transmitter struct {
	w     io.Writer
	mtu   int
	epoch uint16
	seq   int64
}

func (tx *transmitter) write(r *record) error {
	r.epoch, r.seq = tx.epoch, tx.seq
	tx.seq++
	_, err := tx.w.Write(r.marshal(nil))
	return err
}

func (tx *transmitter) writeFlight(raw []byte, rec []int) (err error) {
	last, sent := 0, 0
	for _, to := range rec {
		v := raw[last:to]
		put6(v[5:], tx.seq)
		tx.seq++
		if to-sent > tx.mtu {
			if _, err = tx.w.Write(raw[sent:last]); err != nil {
				return
			}
			sent = last
		}
		last = to
	}
	if sent == last {
		return nil
	}
	_, err = tx.w.Write(raw[sent:last])
	return
}
