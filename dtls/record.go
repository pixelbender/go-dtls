package dtls

import (
	"errors"
)

var (
	errRecordFormat = errors.New("dtls: record format error")
)

const (
	recordChangeCipherSpec uint8 = 20
	recordAlert            uint8 = 21
	recordHandshake        uint8 = 22
)

var changeCipherSpec = []byte{1}

type record struct {
	typ        uint8
	ver, epoch uint16
	seq        int64
	raw        []byte
	payload    marshaler
}

func parseRecord(b []byte) (*record, []byte, error) {
	if len(b) < 13 {
		return nil, nil, errRecordFormat
	}
	_ = b[10]
	r := &record{
		typ:   b[0],
		ver:   uint16(b[1])<<8 | uint16(b[2]),
		epoch: uint16(b[3])<<8 | uint16(b[4]),
		seq:   int64(b[5])<<40 | int64(b[6])<<32 | int64(b[7])<<24 | int64(b[8])<<16 | int64(b[9])<<8 | int64(b[10]),
	}
	if r.raw, b = split2(b[11:]); r.raw == nil {
		return nil, nil, errRecordFormat
	}
	return r, b, nil
}

func (r *record) prepare(b []byte) []byte {
	var v []byte
	v, b = grow(b, 11)
	_ = v[10]
	v[0] = r.typ
	v[1], v[2] = uint8(r.ver>>8), uint8(r.ver)
	v[3], v[4] = uint8(r.epoch>>8), uint8(r.epoch)
	return pack2(b, r.raw, r.payload)
}

func (r *record) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 11)
	_ = v[10]
	v[0] = r.typ
	v[1], v[2] = uint8(r.ver>>8), uint8(r.ver)
	v[3], v[4] = uint8(r.epoch>>8), uint8(r.epoch)
	s := r.seq
	v[5], v[6], v[7], v[8], v[9], v[10] = uint8(s>>40), uint8(s>>32), uint8(s>>24), uint8(s>>16), uint8(s>>8), uint8(s)
	return pack2(b, r.raw, r.payload)
}

func split(b []byte) (v, next []byte) {
	if len(b) >= 1 {
		if n := int(b[0]) + 1; len(b) >= n {
			v, next = b[1:n], b[n:]
		}
	}
	return
}

func split2(b []byte) (v, next []byte) {
	if len(b) >= 2 {
		_ = b[1]
		if n := int(b[0])<<8 | int(b[1]) + 2; len(b) >= n {
			v, next = b[2:n], b[n:]
		}
	}
	return
}

func split3(b []byte) (v, next []byte) {
	if len(b) >= 3 {
		_ = b[2]
		if n := int(b[0])<<16 | int(b[1])<<8 | int(b[2]) + 3; len(b) >= n {
			v, next = b[3:n], b[n:]
		}
	}
	return
}

func pack(b []byte, raw []byte, m marshaler) []byte {
	p := len(b)
	_, b = grow(b, 1)
	b = marshal(b, raw, m)
	b[p] = uint8(len(b) - p - 1)
	return b
}

func pack2(b []byte, raw []byte, m marshaler) []byte {
	p := len(b)
	_, b = grow(b, 2)
	b = marshal(b, raw, m)
	put2(b[p:], len(b)-p-2)
	return b
}

func marshal(b []byte, raw []byte, m marshaler) []byte {
	if raw != nil {
		return append(b, raw...)
	} else if m != nil {
		return m.marshal(b)
	}
	return b
}

func pack3(b []byte, raw []byte, m marshaler) []byte {
	p := len(b)
	_, b = grow(b, 3)
	if raw != nil {
		b = append(b, raw...)
	} else if m != nil {
		b = m.marshal(b)
	}
	put3(b[p:], len(b)-p-3)
	return b
}

func put2(b []byte, n int) {
	_ = b[1]
	b[0], b[1] = uint8(n>>8), uint8(n)
}

func put3(b []byte, n int) {
	_ = b[2]
	b[0], b[1], b[2] = uint8(n>>16), uint8(n>>8), uint8(n)
}

func put6(b []byte, n int64) {
	_ = b[5]
	b[0], b[1], b[2], b[3], b[4], b[5] = uint8(n>>40), uint8(n>>32), uint8(n>>24), uint8(n>>16), uint8(n>>8), uint8(n)
}

func grow(b []byte, n int) (v, next []byte) {
	l := len(b)
	r := l + n
	if r > cap(b) {
		next := make([]byte, (1+((r-1)>>10))<<10)
		if l > 0 {
			copy(next, b[:l])
		}
		b = next
	}
	return b[l:r], b[:r]
}

func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}
