package dtls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"github.com/pkg/errors"
	"io"
	"log"
	"net"
	"sort"
	"time"
)

var DefaultConfig = &Config{
	Rand: rand.Reader,
	MTU:  1400,
	RetransmissionTimeout: 500 * time.Millisecond,
	ReadTimeout:           15 * time.Second,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	},
	SRTPProtectionProfiles: []uint16{
		SRTP_AES128_CM_HMAC_SHA1_80,
		SRTP_AES128_CM_HMAC_SHA1_32,
	},
	MinVersion: VersionDTLS10,
	MaxVersion: VersionDTLS12,
}

type Config struct {
	Rand                   io.Reader
	MTU                    int
	RetransmissionTimeout  time.Duration
	ReadTimeout            time.Duration
	RootCAs                *x509.CertPool
	CipherSuites           []uint16
	SRTPProtectionProfiles []uint16
	MinVersion             uint16
	MaxVersion             uint16
	Logf                   func(format string, args ...interface{})
}

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
		Conn:   c,
		config: config,
		rx: receiver{
			r: c,
		},
		tx: transmitter{
			w:   c,
			mtu: config.MTU,
		},
	}
}

var (
	errTimeout = errors.New("timeout")
)

type handshakeProtocol struct {
	*Conn
	f flight
	d defrag
}

func (p *handshakeProtocol) send(m ...*handshake) {
	r := &record{
		typ:   recordHandshake,
		ver:   p.config.MinVersion,
		epoch: p.tx.epoch,
	}
	p.f.prepare(p.tx.mtu, r, m...)
}

func (p *handshakeProtocol) receive(handle func(h *handshake) (bool, error)) error {
	start, done, rto := time.Now(), false, p.config.RetransmissionTimeout
	if err := p.tx.sendFlight(&p.f); err != nil {
		return err
	}
	for !done {
		d := p.config.ReadTimeout - time.Since(start)
		if d < 0 {
			return errTimeout
		}
		if d > rto {
			d = rto
		}
		p.SetReadDeadline(time.Now().Add(d))
		r, err := p.rx.receive()
		if err != nil {
			if t, ok := err.(interface {
				Timeout() bool
			}); ok && t.Timeout() {
				rto <<= 1
				if err = p.tx.sendFlight(&p.f); err == nil {
					continue
				}
			}
			return err
		}
		switch r.typ {
		case recordHandshake:
			if err = p.d.parse(r.raw); err != nil {
				log.Printf("Warning: %v", err)
				break
			}
			if m := p.d.read(); m != nil {
				done, err = handle(m)
				if err != nil {
					return err
				}
			}
		case recordAlert:
			a, err := parseAlert(r.raw)
			if err != nil {
				return err
			}
			if a.level == levelError {
				return a
			}
		default:
			log.Printf("Unexpected record: %v", r.typ)
		}
	}
	log.Printf("LOL")
	return nil
}

type receiver struct {
	r     io.Reader
	epoch uint16
	seq   int64
	mask  int64
	buf   []byte
	queue []byte
}

func (rx *receiver) upgrade() {
	rx.mask = 0
	rx.seq = 0
	rx.epoch++
}

func (rx *receiver) receive() (r *record, err error) {
	if rx.buf == nil {
		rx.buf = make([]byte, 4096)
	}
	for {
		for len(rx.queue) > 0 {
			r, rx.queue, err = parseRecord(rx.queue)
			if err != nil || !rx.valid(r) {
				rx.queue = nil
				break
			}
			return r, nil
		}
		n, err := rx.r.Read(rx.buf)
		if err != nil {
			return nil, err
		}
		rx.queue = rx.buf[:n]
		log.Printf("Receive: %s", hex.Dump(rx.queue))
	}
}

func (rx *receiver) valid(r *record) bool {
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
	epoch uint16
	seq   int64
	mtu   int
}

func (tx *transmitter) upgrade() {
	tx.seq = 0
	tx.epoch++
}

func (tx *transmitter) write(b []byte) error {
	log.Printf("Write: %s", hex.Dump(b))
	_, err := tx.w.Write(b)
	return err
}

func (tx *transmitter) sendRecord(r *record) error {
	r.epoch, r.seq = tx.epoch, tx.seq
	tx.seq++
	return tx.write(r.marshal(nil))
}

func (tx *transmitter) sendAlert(alert uint8) error {
	return tx.sendRecord(&record{
		typ: recordAlert,
		ver: VersionDTLS10,
		raw: []byte{levelError, alert},
	})
}

func (tx *transmitter) sendFlight(f *flight) error {
	last, sent := 0, 0
	for _, to := range f.rec {
		v := f.raw[last:to]
		put6(v[5:], tx.seq)
		tx.seq++
		if to-sent > tx.mtu {
			if err := tx.write(f.raw[sent:last]); err != nil {
				return err
			}
			sent = last
		}
		last = to
	}
	if sent == last {
		return nil
	}
	return tx.write(f.raw[sent:last])
}

type flight struct {
	pos int
	seq int
	raw []byte
	rec []int
}

func (f *flight) reset() {
	if len(f.raw) > 0 {
		f.raw = f.raw[:0]
	}
	if len(f.rec) > 0 {
		f.rec = f.rec[:0]
	}
	f.pos = 0
}

func (f *flight) add(mtu int, r *record) {
	if mtu < 26 {
		panic("dtls: mtu is too small")
	}
	b := f.raw
	from := len(b)
	b = r.prepare(b)
	to := len(b)
	n, max := to-from, mtu-f.pos
	l := n - 25
	put3(b[from+14:], l)
	if n > max {
		f.pos, max = 0, mtu
	}
	if n <= max {
		f.pos += n
		f.rec = append(f.rec, to)
		f.raw = b
		return
	}
	m := max - 25
	c := l / m
	if l > m*c {
		c++
	}
	_, b = grow(b, (c-1)*25)
	put2(b[from+11:], m+12)
	put3(b[from+22:], m)
	v := b[from:]
	for i := c - 1; i > 0; i-- {
		p, off := v[i*max:], i*m
		if len(p) > max {
			p = p[:max]
		}
		s := copy(p[25:], v[25+off:])
		copy(p, v[:19])
		put2(p[11:], s+12)
		put3(p[19:], off)
		put3(p[22:], s)
	}
	for i, m := 0, len(b); i < c; i++ {
		to := from + (i+1)*max
		if to > m {
			to = m
		}
		f.rec = append(f.rec, to)
	}
	f.raw = b
}

func (f *flight) prepare(mtu int, r *record, m ...*handshake) {
	f.reset()
	for _, it := range m {
		it.seq = f.seq
		r.payload = it
		f.add(mtu, r)
		f.seq++
	}
}

type defrag struct {
	seq    int
	queues [16]*queue
}

func (d *defrag) parse(b []byte) error {
	h, err := parseHandshake(b)
	if err != nil {
		return err
	}
	ds := h.seq - d.seq
	if ds < 0 || ds > 15 {
		return errHandshakeSequence
	}
	i := h.seq & 0xf
	q := d.queues[i]
	if q == nil {
		q = &queue{}
		d.queues[i] = q
	}
	if len(q.h) == 0 {
		if h.len < 0 || h.len > 0x1000 {
			return errHandshakeFormat
		}
		_, q.raw = grow(q.raw[:0], h.len)
	} else {
		for _, it := range q.h {
			if it.off == h.off && len(it.raw) == len(h.raw) {
				return nil
			}
		}
	}
	if h.off < 0 || h.off+len(h.raw) > len(q.raw) {
		return errHandshakeFormat
	}
	copy(q.raw[h.off:], h.raw)
	q.h = append(q.h, h)
	sort.Sort(q)
	return nil
}

func (d *defrag) read() *handshake {
	n, q := 0, d.queues[d.seq&0xf]
	if q == nil {
		return nil
	}
	for _, h := range q.h {
		if next := h.off + len(h.raw); h.off <= n && next > n {
			n = next
		}
	}
	if n == len(q.raw) {
		h := q.h[0]
		h.off, h.raw, q.raw = 0, q.raw, q.raw[:0]
		d.seq++
		return h
	}
	return nil
}

type queue struct {
	h   []*handshake
	raw []byte
}

func (q *queue) Len() int {
	return len(q.h)
}

func (q *queue) Swap(i, j int) {
	r := q.h
	r[i], r[j] = r[j], r[i]
}

func (q *queue) Less(i, j int) bool {
	a, b := q.h[i], q.h[j]
	return a.off < b.off
}
