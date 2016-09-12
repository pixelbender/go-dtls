package dtls

import (
	"encoding/hex"
	"io"
	"log"
)

type writer interface {
	io.Writer
	Next(n int) (b []byte)
}

type bufferWriter struct {
	buf []byte
	pos int
}

func (w *bufferWriter) Next(n int) (b []byte) {
	p := w.pos + n
	if len(w.buf) < p {
		b := make([]byte, (1+((p-1)>>10))<<10)
		if w.pos > 0 {
			copy(b, w.buf[:w.pos])
		}
		w.buf = b
	}
	b, w.pos = w.buf[w.pos:p], p
	return
}

func (w *bufferWriter) Write(b []byte) (int, error) {
	return copy(w.Next(len(b)), b), nil
}

func (w *bufferWriter) Reset() {
	w.pos = 0
}

func (w *bufferWriter) Bytes() []byte {
	return w.buf[:w.pos]
}

type sender struct {
	bufferWriter
	epoch uint16
	seq   uint64
}

type handshakeEncoder struct {
	*sender
	ver   uint16
	mseq  uint16
	mtu   int
	frag  []int
	split int
}

func (w *handshakeEncoder) WriteMessage(typ uint8, msg handshakeMsg) {
	f := len(w.frag)
	w.nextFragment()

	msg.Marshal(w)
	n := len(w.frag)
	w.frag = append(w.frag, w.pos)

	sum := 0
	for i := f; i < n; i++ {
		from, to := w.frag[i], w.frag[i+1]
		sum += to - from - 25
	}

	off := 0
	for i := f; i < n; i++ {
		from, to := w.frag[i], w.frag[i+1]
		s := to - from - 25
		b := w.buf[from:to]
		b[0] = recordHandshake
		be.PutUint16(b[1:], w.ver)
		be.PutUint64(b[3:], uint64(w.epoch<<48)|uint64(w.seq))
		be.PutUint16(b[11:], uint16(s+12))
		w.seq++
		b[13] = typ
		putInt24(b[14:], sum)
		be.PutUint16(b[17:], w.mseq)
		putInt24(b[19:], off)
		putInt24(b[22:], s)
		off += s
	}
	w.mseq++
}

func (w *handshakeEncoder) nextFragment() {
	w.frag = append(w.frag, w.pos)
	w.bufferWriter.Next(25)
	w.split = w.pos + w.mtu
}

func (w *handshakeEncoder) Reset() {
	w.bufferWriter.Reset()
	if w.frag != nil {
		w.frag = w.frag[:0]
	}
}

func (w *handshakeEncoder) WriteTo(conn io.Writer) (l int, err error) {
	var s int
	for i, n := 0, len(w.frag)-1; i < n; i++ {
		from, to := w.frag[i], w.frag[i+1]
		if from < to {
			log.Printf("SEND %s", hex.Dump(w.buf[from:to]))
			if s, err = conn.Write(w.buf[from:to]); err != nil {
				return
			}
			l += s
		}
	}
	return
}

func (w *handshakeEncoder) Next(n int) []byte {
	if w.split < w.pos+n {
		w.nextFragment()
	}
	return w.bufferWriter.Next(n)
}

func (w *handshakeEncoder) Write(b []byte) (int, error) {
	l := 0
	for len(b) > 0 {
		n := len(b)
		r := w.split - w.pos
		if r < n {
			w.bufferWriter.Write(b[:r])
			w.nextFragment()
			b = b[r:]
			l += r
		} else {
			w.bufferWriter.Write(b)
			l += n
			break
		}
	}
	return l, nil
}

func putInt24(b []byte, v int) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func putSlice16(w writer, v []uint16) {
	n := len(v) << 1
	b := w.Next(2)
	be.PutUint16(b, uint16(n))
	for _, it := range v {
		be.PutUint16(w.Next(2), it)
	}
}

func putSlice8(w writer, v []uint8) {
	b := w.Next(1)
	b[0] = uint8(len(v))
	w.Write(v)
}

func putExtensions(w writer, v map[uint16]Extension) {
	n := 0
	for typ, it := range v {
		if it == nil {
			n += 4
		} else {
			b := it.Bytes()
			v[typ] = rawExtension(b)
			n += 4 + len(b)
		}
	}
	be.PutUint16(w.Next(2), uint16(n))
	for typ, it := range v {
		b := w.Next(4)
		be.PutUint16(b, typ)
		if it == nil {
			be.PutUint16(b[2:], 0)
		} else {
			e := []byte(it.(rawExtension))
			be.PutUint16(b[2:], uint16(len(e)))
			w.Write(e)
		}
	}
}
