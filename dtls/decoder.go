package dtls

import (
	"encoding/hex"
	"errors"
	"io"
	"log"
	"sort"
	"strconv"
)

var ErrFormat = errors.New("dtls: incorrect format")

type reader interface {
	Next(n int) ([]byte, error)
	Len() int
}

const (
	maxPacketSize    = 4096
	maxUnreadRecords = 64
)

type bufferReader struct {
	buf []byte
	pos int
}

func (r *bufferReader) Next(n int) ([]byte, error) {
	p := r.pos + n
	if len(r.buf) < r.pos+n {
		return nil, io.EOF
	}
	off := r.pos
	r.pos = p
	return r.buf[off:p], nil
}

func (r *bufferReader) Len() int {
	return len(r.buf) - r.pos
}

type receiver struct {
	inner   io.Reader
	buf     [maxPacketSize]byte
	records recordSeq
	epoch   uint16
	seq     uint64
}

func (r *receiver) Read() (*record, error) {
	for {
		if len(r.records) > 0 {
			if rec := r.records[0]; rec.seq == r.seq {
				r.records = r.records[1:]
				r.seq++
				return rec, nil
			}
		}
		n, err := r.inner.Read(r.buf[:])
		if err != nil {
			return nil, err
		}
		r.fill(r.buf[:n])
	}
}

func (r *receiver) fill(b []byte) (err error) {
	log.Printf("RECV %s", hex.Dump(b))
	rec := new(record)
	if err = rec.read(b); err != nil {
		return err
	}
	if rec.seq < r.seq {
		return nil
	}
	r.records = append(r.records, rec)
	n := 0
	for _, it := range r.records {
		it.age++
		if it.seq < r.seq || it.seq > r.seq+maxUnreadRecords || it.age > maxUnreadRecords {
			continue
		}
		r.records[n] = it
		n++
	}
	r.records = r.records[:n]
	sort.Sort(r.records)
	return
}

type handshakeDecoder struct {
	*receiver
	ver  uint16
	mseq uint16
}

func (r *handshakeDecoder) ReadMessage() (msg handshakeMsg, err error) {
	var rec *record
	var buf []byte
	var off int
	for {
		if rec, err = r.Read(); err != nil {
			return
		}
		f := new(fragment)
		if err = f.read(rec.buf); err != nil {
			return
		}
		if f.off != off {
			return nil, ErrFormat
		}
		if buf == nil {
			buf = make([]byte, f.sum)
		}
		if off += copy(buf[off:], f.buf); off < len(buf) {
			continue
		}
		msg = newMessage(f.typ)
		if msg == nil {
			return nil, errors.New("dtls: unsupported handshake message: " + strconv.Itoa(int(f.typ)))
		}
		if err = msg.Unmarshal(&bufferReader{buf: buf}); err != nil {
			return nil, err
		}
		return
	}
}

func getInt24(b []byte) int {
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

func getSlice16(r reader) (v []uint16, err error) {
	var b []byte
	if b, err = r.Next(2); err != nil {
		return
	}
	n := int(be.Uint16(b))
	if b, err = r.Next(n); err != nil {
		return
	}
	for i, s := 0, n-1; i < s; i += 2 {
		v = append(v, be.Uint16(b[i:]))
	}
	return
}

func getSlice8(r reader) (v []uint8, err error) {
	var b []byte
	if b, err = r.Next(1); err != nil {
		return
	}
	n := int(b[0])
	if n > 0 {
		v, err = r.Next(n)
	}
	return
}

func getExtensions(r reader) (v map[uint16]Extension, err error) {
	var b []byte
	if b, err = r.Next(2); err != nil {
		return
	}
	n := int(be.Uint16(b))
	v = make(map[uint16]Extension)
	for n > 0 {
		if b, err = r.Next(4); err != nil {
			return
		}
		typ, s := be.Uint16(b), int(be.Uint16(b[2:]))
		if b, err = r.Next(s); err != nil {
			return
		}
		v[typ] = rawExtension(b)
		n -= 4 + s
	}
	return
}
