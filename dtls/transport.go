package dtls

import (
	"net"
	"sort"
	"sync/atomic"
	"time"
)

type transport struct {
	net.Conn
	config *Config
	ver    uint16
	epoch  uint16
	rx     struct {
		seq  int64
		mask int64
		buf  []byte
		pos  int
	}
	tx struct {
		seq int64
	}
}

func (t *transport) readRecord() (*record, error) {
	b := t.rx.buf
	if b == nil {
		b = make([]byte, 0, 4096)
		t.rx.buf = b
	}
	for {
		for t.rx.pos < len(b) {
			r, n, err := parseRecord(b[t.rx.pos:])
			if err != nil {
				t.rx.pos = len(b)
				return r, err
			}
			t.rx.pos += n
			if t.canReceive(r) {
				return r, nil
			}
		}
		n, err := t.Read(b[:cap(b)])
		if err != nil {
			return nil, err
		}
		t.rx.buf = b[:n]
	}
}

func (t *transport) canReceive(r *record) bool {
	if r.epoch != t.epoch {
		return false
	}
	// TODO: prevent from seq corruption
	d := r.seq - t.rx.seq
	if d > 0 {
		if d < 64 {
			t.rx.mask = (t.rx.mask << uint(d)) | 1
		} else {
			t.rx.mask = 1
		}
		t.rx.seq = r.seq
		return true
	}
	if d = -d; d >= 64 {
		return false
	}
	if b := int64(1) << uint(d); t.rx.mask&b == 0 {
		t.rx.mask |= b
		return true
	}
	return false
}

func (t *transport) sendAlert(alert uint8) error {
	return t.writeRecord(&record{
		typ: recordAlert,
		ver: t.ver,
		raw: []byte{levelError, alert},
	})
}

func (t *transport) writeRecord(r *record) error {
	r.ver, r.epoch, r.seq = t.ver, t.epoch, atomic.AddInt64(&t.tx.seq, 1)-1
	_, err := t.Write(r.marshal(nil))
	return err
}

func (t *transport) writeFlight(raw []byte, rec []int) error {
	sent, last := 0, 0
	for _, to := range rec {
		v := raw[last:to]
		put6(v[5:], atomic.AddInt64(&t.tx.seq, 1)-1)
		if to-sent > t.config.getMTU() {
			if _, err := t.Write(raw[sent:last]); err != nil {
				return err
			}
			sent = last
		}
		last = to
	}
	if sent == last {
		return nil
	}
	_, err := t.Write(raw[sent:last])
	return err
}

type handshakeTransport struct {
	*transport
	log []byte
	out struct {
		seq  int
		raw  []byte
		rec  []int
		last int
	}
	in struct {
		seq   int
		queue [16]*handshakeQueue
	}
}

func (t *handshakeTransport) reset() {
	if t.log != nil {
		t.log = t.log[:0]
	}
	t.clearFlight()
}

func (t *handshakeTransport) roundTrip(handle func(h *handshake) (bool, error)) error {
	defer t.clearFlight()
	if err := t.sendFlight(); err != nil {
		return err
	}
	var (
		start = time.Now()
		rto   = t.config.RetransmissionTimeout
	)
	defer t.SetReadDeadline(time.Time{})
	for {
		d := t.config.ReadTimeout - time.Since(start)
		if d < 0 {
			return errHandshakeTimeout
		}
		if d > rto {
			d = rto
		}
		t.SetReadDeadline(time.Now().Add(d))
		h, err := t.readHandshake()
		if err != nil {
			if e, ok := err.(interface {
				Timeout() bool
			}); ok && e.Timeout() {
				rto <<= 1
				if err = t.sendFlight(); err != nil {
					continue
				}
			}
			return err
		}
		if done, err := handle(h); err != nil {
			return err
		} else if done {
			break
		}
	}
	return nil
}

func (t *handshakeTransport) prepare(h *handshake) {
	h.seq = t.out.seq
	t.out.seq++
	t.prepareRecord(&record{typ: recordHandshake, payload: h})
}

func (t *handshakeTransport) prepareRecord(r *record) {
	r.ver, r.epoch = t.ver, t.epoch
	b := t.out.raw
	pos := len(b)
	b = r.prepare(b)
	v := b[pos:]
	mtu := t.config.getMTU()
	n, max := len(v), mtu-len(b)+t.out.last
	if n > max {
		t.out.last, max = len(b), mtu
	}
	if r.typ == recordHandshake {
		put3(v[14:], n-25)
		t.log = append(t.log, v[25:]...)
	}
	if n <= max || r.typ != recordHandshake {
		t.out.rec = append(t.out.rec, t.out.last+n)
		t.out.raw = b
		return
	}
	l, m := n-25, max-25
	c := l / m
	s := l - m*c
	if s == 0 {
		c--
	}
	_, b = grow(b, c*25)
	dst := b[pos:]
	for i := c; i >= 0; i-- {
		d, off, s := dst[i*max:], i*m, m
		if len(d) > max {
			d = d[:max]
		}
		if i > 0 {
			s = copy(d[25:], v[25+off:])
			copy(d, v[:19])
		}
		put2(d[11:], s+12)
		put3(d[19:], off)
		put3(d[22:], s)
	}
	for i := 0; i < c; i++ {
		t.out.last += max
		t.out.rec = append(t.out.rec, t.out.last)
	}
	if s > 0 {
		t.out.rec = append(t.out.rec, t.out.last+s)
	}
	t.out.raw = b
}

func (t *handshakeTransport) sendFlight() error {
	return t.writeFlight(t.out.raw, t.out.rec)
}

func (t *handshakeTransport) clearFlight() {
	if t.out.raw != nil {
		t.out.raw = t.out.raw[:0]
	}
	if t.out.rec != nil {
		t.out.rec = t.out.rec[:0]
	}
	t.out.last = 0
}

func (t *handshakeTransport) parse(b []byte) error {
	h, err := parseHandshake(b)
	if err != nil {
		return err
	}
	ds := h.seq - t.in.seq
	if ds < 0 || ds > 15 {
		return errHandshakeSequence
	}
	i := h.seq & 0xf
	q := t.in.queue[i]
	if q == nil {
		if h.len < 0 || h.len > 0x1000 {
			return errHandshakeMessageTooBig
		}
		q = &handshakeQueue{
			raw: make([]byte, h.len),
		}
		t.in.queue[i] = q
	}
	if m := h.off + len(h.raw); h.off < 0 || m > len(q.raw) {
		return errHandshakeMessageOutOfBounds
	}
	copy(q.raw[h.off:], h.raw)
	q.h = append(q.h, h)
	sort.Sort(q)
	return nil
}

func (t *handshakeTransport) next() *handshake {
	id := t.in.seq & 0xf
	q := t.in.queue[id]
	if q == nil {
		return nil
	}
	last := 0
	for _, h := range q.h {
		if next := h.off + len(h.raw); h.off <= last && next > last {
			last = next
		}
	}
	if last == len(q.raw) {
		h := q.h[0]
		h.off, h.raw = 0, q.raw
		t.in.queue[id] = nil
		t.in.seq++
		return h
	}
	return nil
}

func (t *handshakeTransport) readHandshake() (*handshake, error) {
	for {
		h := t.next()
		if h != nil {
			t.log = append(t.log, h.raw...)
			h.raw = clone(h.raw)
			return h, nil
		}
		r, err := t.readRecord()
		if err != nil {
			return nil, err
		}
		switch r.typ {
		case recordAlert:
			a, err := parseAlert(r.raw)
			if err != nil {
				return nil, err
			}
			if a.level == levelError {
				return nil, a
			}
		case recordHandshake:
			if err = t.parse(r.raw); err != nil {
				return nil, err
			}
		default:
			return nil, errUnexpectedMessage
		}
	}
}

type handshakeQueue struct {
	h   []*handshake
	raw []byte
}

func (q *handshakeQueue) Len() int {
	return len(q.h)
}

func (q *handshakeQueue) Swap(i, j int) {
	r := q.h
	r[i], r[j] = r[j], r[i]
}

func (q *handshakeQueue) Less(i, j int) bool {
	a, b := q.h[i], q.h[j]
	return a.off < b.off
}
