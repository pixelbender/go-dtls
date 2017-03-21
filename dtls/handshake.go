package dtls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"sort"
	"time"
)

var (
	errHandshakeFormat          = errors.New("dtls: handshake format error")
	errCertificateRequestFormat = errors.New("dtls: certificateRequest format error")
	errClientHelloFormat        = errors.New("dtls: clientHello format error")
	errServerHelloFormat        = errors.New("dtls: serverHello format error")
	errHelloVerifyRequestFormat = errors.New("dtls: helloVerifyRequest format error")
	errCertificateFormat        = errors.New("dtls: certificate format error")
	errServerKeyExchangeFormat  = errors.New("dtls: serverKeyExchange format error")
	errClientKeyExchangeFormat  = errors.New("dtls: clientkeyExchange format error")
	errCertificateVerifyFormat  = errors.New("dtls: certificateVerify format error")

	errHandshakeSequence = errors.New("dtls: handshake sequence error")
	errHandshakeTimeout  = errors.New("dtls: handshake timeout")
	errHandshakeError    = errors.New("dtls: handshake error")

	errUnexpectedMessage = errors.New("dtls: unexpected message")
)

const (
	handshakeClientHello        uint8 = 1
	handshakeServerHello        uint8 = 2
	handshakeHelloVerifyRequest uint8 = 3
	handshakeCertificate        uint8 = 11
	handshakeServerKeyExchange  uint8 = 12
	handshakeCertificateRequest uint8 = 13
	handshakeServerHelloDone    uint8 = 14
	handshakeCertificateVerify  uint8 = 15
	handshakeClientKeyExchange  uint8 = 16
	handshakeFinished           uint8 = 20
)

const (
	keyRSA  = 1
	keyECDH = 2
)

const (
	compNone uint8 = 0
)

var supportedCompression = []uint8{
	compNone,
}

type handshakeProtocol struct {
	*Conn
	enc handshakeEncoder
	dec handshakeDecoder
	buf bytes.Buffer
}

func (c *handshakeProtocol) reset(clearHash bool) {
	if clearHash {
		c.buf.Reset()
	}
	c.enc.reset()
}

func (c *handshakeProtocol) write(h *handshake) {
	c.enc.w = &c.buf
	c.enc.write(&record{
		typ:   recordHandshake,
		ver:   c.config.MinVersion,
		epoch: c.tx.epoch,
	}, h)
}

func (c *handshakeProtocol) changeCipherSpec() {
	c.enc.w = &c.buf
	c.enc.writeRecord(&record{
		typ:   recordChangeCipherSpec,
		ver:   c.config.MinVersion,
		epoch: c.tx.epoch,
		raw:   changeCipherSpec,
	})
}

func (c *handshakeProtocol) flight(handle func(h *handshake) (bool, error)) error {
	start, done, rto := time.Now(), false, c.config.RetransmissionTimeout
	if err := c.tx.writeFlight(c.enc.raw, c.enc.rec); err != nil {
		return err
	}
	for !done {
		d := c.config.ReadTimeout - time.Since(start)
		if d < 0 {
			return errHandshakeTimeout
		}
		if d > rto {
			d = rto
		}
		c.SetReadDeadline(time.Now().Add(d))
		r, err := c.rx.read()
		if err != nil {
			if t, ok := err.(interface {
				Timeout() bool
			}); ok && t.Timeout() {
				rto <<= 1
				if err = c.tx.writeFlight(c.enc.raw, c.enc.rec); err == nil {
					continue
				}
			}
			return err
		}
		switch r.typ {
		case recordHandshake:
			if !c.dec.parse(r.raw) {
				break
			}
			if h := c.dec.read(); h != nil {
				h.raw = clone(h.raw) // TODO: append and slice finish hash buffer
				c.buf.Write(h.raw)
				done, err = handle(h)
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
				// TODO: check if warnings corrupt handshake
				return a
			}
		default:
			log.Printf("Unexpected record: %v", r.typ)
		}
	}
	return nil
}

type marshaler interface {
	marshal([]byte) []byte
}

type handshake struct {
	typ     uint8
	len     int
	seq     int
	off     int
	raw     []byte
	message marshaler
}

func parseHandshake(b []byte) (*handshake, error) {
	if len(b) < 12 {
		return nil, errHandshakeFormat
	}
	_ = b[8]
	h := &handshake{
		typ: b[0],
		len: int(b[1])<<16 | int(b[2])<<8 | int(b[3]),
		seq: int(b[4])<<8 | int(b[5]),
		off: int(b[6])<<16 | int(b[7])<<8 | int(b[8]),
	}
	if h.raw, _ = split3(b[9:]); h.raw == nil {
		return nil, errHandshakeFormat
	}
	return h, nil
}

func (h *handshake) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 9)
	_ = v[8]
	v[0] = h.typ
	v[1], v[2], v[3] = uint8(h.len>>16), uint8(h.len>>8), uint8(h.len)
	v[4], v[5] = uint8(h.seq>>8), uint8(h.seq)
	v[6], v[7], v[8] = uint8(h.off>>16), uint8(h.off>>8), uint8(h.off)
	return pack3(b, h.raw, h.message)
}

type clientHello struct {
	ver          uint16
	random       []byte
	sessionID    []byte
	cookie       []byte
	cipherSuites []uint16
	compMethods  []uint8
	raw          []byte
	*extensions
}

func parseClientHello(b []byte) (*clientHello, error) {
	if len(b) < 34 {
		return nil, errClientHelloFormat
	}
	_ = b[33]
	h := &clientHello{
		ver:    uint16(b[0])<<8 | uint16(b[1]),
		random: b[2:34],
	}
	var v []byte
	if h.sessionID, b = split(b[34:]); b == nil {
		return nil, errClientHelloFormat
	}
	if h.cookie, b = split(b); b == nil {
		return nil, errClientHelloFormat
	}
	if v, b = split2(b); b == nil {
		return nil, errClientHelloFormat
	}
	h.cipherSuites = make([]uint16, len(v)>>1)
	for i := range h.cipherSuites {
		_ = v[1]
		h.cipherSuites[i], v = uint16(v[0])<<8|uint16(v[1]), v[2:]
	}
	if h.compMethods, b = split(b); b == nil {
		return nil, errClientHelloFormat
	}
	if h.raw, b = split2(b); b == nil {
		return nil, errClientHelloFormat
	}
	return h, nil
}

func (h *clientHello) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 34)
	_ = v[33]
	v[0], v[1] = uint8(h.ver>>8), uint8(h.ver)
	copy(v[2:], h.random)
	b = pack(b, h.sessionID, nil)
	b = pack(b, h.cookie, nil)
	n := len(h.cipherSuites) << 1
	v, b = grow(b, 2+n)
	_ = v[1]
	v[0], v[1], v = uint8(n>>8), uint8(n), v[2:]
	for _, s := range h.cipherSuites {
		_ = v[1]
		v[0], v[1], v = uint8(s>>8), uint8(s), v[2:]
	}
	b = pack(b, h.compMethods, nil)
	return pack2(b, h.raw, h.extensions)
}

type serverHello struct {
	ver         uint16
	random      []byte
	sessionID   []byte
	cipherSuite uint16
	compMethod  uint8
	raw         []byte
	*extensions
}

func parseServerHello(b []byte) (*serverHello, error) {
	if len(b) < 34 {
		return nil, errServerHelloFormat
	}
	_ = b[33]
	h := &serverHello{
		ver:    uint16(b[0])<<8 | uint16(b[1]),
		random: b[2:34],
	}
	if h.sessionID, b = split(b[34:]); b == nil {
		return nil, errServerHelloFormat
	}
	if len(b) < 3 {
		return nil, errServerHelloFormat
	}
	_ = b[2]
	h.cipherSuite = uint16(b[0])<<8 | uint16(b[1])
	h.compMethod = b[2]
	if h.raw, b = split2(b[3:]); b == nil {
		return nil, errServerHelloFormat
	}
	return h, nil
}

func (h *serverHello) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 34)
	_ = v[33]
	v[0], v[1] = uint8(h.ver>>8), uint8(h.ver)
	copy(v[2:], h.random)
	b = pack(b, h.sessionID, nil)
	v, b = grow(b, 3)
	_ = v[2]
	v[0], v[1] = uint8(h.cipherSuite>>8), uint8(h.cipherSuite)
	v[2] = h.compMethod
	return pack2(b, h.raw, h.extensions)
}

type helloVerifyRequest struct {
	ver    uint16
	cookie []byte
}

func parseHelloVerifyRequest(b []byte) (*helloVerifyRequest, error) {
	if len(b) < 3 {
		return nil, errHelloVerifyRequestFormat
	}
	_ = b[1]
	h := &helloVerifyRequest{
		ver: uint16(b[0])<<8 | uint16(b[1]),
	}
	if h.cookie, b = split(b[2:]); b == nil {
		return nil, errHelloVerifyRequestFormat
	}
	return h, nil
}

func (r *helloVerifyRequest) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 2)
	_ = v[1]
	v[0], v[1] = uint8(r.ver>>8), uint8(r.ver)
	return pack(b, r.cookie, nil)
}

type certificate struct {
	raw  [][]byte
	cert []*x509.Certificate
}

func parseCertificate(b []byte) (*certificate, error) {
	if b, _ = split3(b); b == nil {
		return nil, errCertificateFormat
	}
	var v []byte
	c := &certificate{}
	for len(b) > 0 {
		if v, b = split3(b); b == nil {
			return nil, errCertificateFormat
		}
		cert, err := x509.ParseCertificate(v)
		if err != nil {
			return nil, err
		}
		c.raw = append(c.raw, v)
		c.cert = append(c.cert, cert)
	}
	return c, nil
}

func (c *certificate) marshal(b []byte) []byte {
	p := len(b)
	_, b = grow(b, 3)
	for _, v := range c.raw {
		b = pack3(b, v, nil)
	}
	n, v := len(b)-p-3, b[p:]
	_ = v[2]
	v[0], v[1], v[2] = uint8(n>>16), uint8(n>>8), uint8(n)
	return b
}

type serverKeyExchange struct {
	curve uint16
	pub   []byte
	sign  []byte
}

func parseServerKeyExchange(b []byte) (*serverKeyExchange, error) {
	if len(b) < 4 {
		return nil, errServerKeyExchangeFormat
	}
	_ = b[2]
	if b[0] != 3 {
		return nil, errServerKeyExchangeFormat
	}
	e := &serverKeyExchange{
		curve: uint16(b[1])<<8 | uint16(b[2]),
	}
	if e.pub, b = split(b[3:]); b == nil {
		return nil, errServerKeyExchangeFormat
	}
	if e.sign, b = split2(b); b == nil {
		return nil, errServerKeyExchangeFormat
	}
	return e, nil
}

func (e *serverKeyExchange) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 3)
	_ = b[2]
	v[0], v[1], v[2] = 3, uint8(e.curve>>8), uint8(e.curve)
	b = pack(b, e.pub, nil)
	return pack2(b, e.sign, nil)
}

type clientKeyExchange struct {
	typ uint8
	pub []byte
}

func parseClientKeyExchange(typ uint8, b []byte) (*clientKeyExchange, error) {
	e := &clientKeyExchange{typ: typ}
	switch typ {
	case keyRSA:
		if e.pub, b = split2(b); b == nil {
			return nil, errClientKeyExchangeFormat
		}
	case keyECDH:
		if e.pub, b = split(b); b == nil {
			return nil, errClientKeyExchangeFormat
		}
	default:
		return nil, errUnsupportedKeyExchangeAlgorithm
	}
	return e, nil
}

func (e *clientKeyExchange) marshal(b []byte) []byte {
	switch e.typ {
	case keyRSA:
		return pack2(b, e.pub, nil)
	case keyECDH:
		return pack(b, e.pub, nil)
	}
	return b
}

type certificateVerify struct {
	sign []byte
}

func parseCertificateVerify(b []byte) (*certificateVerify, error) {
	e := &certificateVerify{}
	if e.sign, b = split2(b); b == nil {
		return nil, errCertificateVerifyFormat
	}
	return e, nil
}

func (e *certificateVerify) marshal(b []byte) []byte {
	return pack2(b, e.sign, nil)
}

type certificateRequest struct {
	types []uint8
	names []byte
}

func parseCertificateRequest(b []byte) (*certificateRequest, error) {
	r := &certificateRequest{}
	if r.types, b = split(b); b == nil {
		return nil, errCertificateRequestFormat
	}
	if r.names, b = split2(b); b == nil {
		return nil, errCertificateRequestFormat
	}
	return r, nil
}

func (r *certificateRequest) marshal(b []byte) []byte {
	b = pack(b, r.types, nil)
	return pack2(b, r.names, nil)
}

type handshakeEncoder struct {
	mtu int
	pos int
	raw []byte
	rec []int
	seq int
	w   io.Writer
}

func (e *handshakeEncoder) reset() {
	if len(e.raw) > 0 {
		e.raw = e.raw[:0]
	}
	if len(e.rec) > 0 {
		e.rec = e.rec[:0]
	}
	e.pos = 0
}

func (e *handshakeEncoder) write(r *record, h *handshake) {
	r.payload, h.seq = h, e.seq
	e.seq++
	e.writeRecord(r)
}

func (e *handshakeEncoder) writeRecord(r *record) {
	if e.mtu < 26 {
		panic("dtls: mtu is too small")
	}
	b := e.raw
	from := len(b)
	b = r.prepare(b)
	to := len(b)
	if e.w != nil && r.typ == recordHandshake {
		e.w.Write(b[from:to])
	}
	n, max := to-from, e.mtu-e.pos
	l := n - 25
	if r.typ == recordHandshake {
		put3(b[from+14:], l)
	}
	if n > max {
		e.pos, max = 0, e.mtu
	}
	if n <= max || r.typ != recordHandshake {
		e.pos += n
		e.rec = append(e.rec, to)
		e.raw = b
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
		e.rec = append(e.rec, to)
	}
	e.raw = b
}

type handshakeDecoder struct {
	seq int
	que [16]*queue
}

func (d *handshakeDecoder) parse(b []byte) bool {
	h, err := parseHandshake(b)
	if err != nil {
		log.Printf("dtls: handshake parse error: %v", err)
		return false
	}
	ds := h.seq - d.seq
	if ds < 0 || ds > 15 {
		log.Printf("dtls: handshake sequence %d > %d", h.seq, d.seq)
		return false
	}
	i := h.seq & 0xf
	q := d.que[i]
	if q == nil {
		if h.len < 0 || h.len > 0x1000 {
			log.Printf("dtls: handshake message is too big: %d bytes", h.len)
			return false
		}
		q = &queue{raw: make([]byte, h.len)}
		d.que[i] = q
	} else {
		for _, it := range q.h {
			if it.off == h.off && len(h.raw) == len(it.raw) {
				log.Printf("dtls: handshake message duplicate")
				return false
			}
		}
	}
	if m := h.off + len(h.raw); h.off < 0 || m > len(q.raw) {
		log.Printf("dtls: handshake message out of bounds %d:%d max %d", h.off, m, len(q.raw))
		return false
	}
	copy(q.raw[h.off:], h.raw)
	q.h = append(q.h, h)
	sort.Sort(q)
	return true
}

func (d *handshakeDecoder) read() *handshake {
	n, q := 0, d.que[d.seq&0xf]
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
		h.off, h.raw = 0, q.raw
		d.que[d.seq&0xf] = nil
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
