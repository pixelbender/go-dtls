package dtls

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	errHandshakeFormat   = errors.New("dtls: handshake format error")
	errHandshakeSequence = errors.New("dtls: handshake sequence error")
	errServerKeyExchange = errors.New("dtls: server key exchange format error")
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
	compNone uint8 = 0
)

var supportedCompression = []uint8{
	compNone,
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
		return nil, errHandshakeFormat
	}
	_ = b[33]
	h := &clientHello{
		ver:    uint16(b[0])<<8 | uint16(b[1]),
		random: b[2:34],
	}
	var v []byte
	if h.sessionID, b = split(b[34:]); b == nil {
		return nil, errHandshakeFormat
	}
	if h.cookie, b = split(b); b == nil {
		return nil, errHandshakeFormat
	}
	if v, b = split2(b); b == nil {
		return nil, errHandshakeFormat
	}
	h.cipherSuites = make([]uint16, len(v)>>1)
	for i := range h.cipherSuites {
		_ = v[1]
		h.cipherSuites[i], v = uint16(v[0])<<8|uint16(v[1]), v[2:]
	}
	if h.compMethods, b = split(b); b == nil {
		return nil, errHandshakeFormat
	}
	if h.raw, b = split2(b); b == nil {
		return nil, errHandshakeFormat
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
		return nil, errHandshakeFormat
	}
	_ = b[33]
	h := &serverHello{
		ver:    uint16(b[0])<<8 | uint16(b[1]),
		random: b[2:34],
	}
	if h.sessionID, b = split(b[34:]); b == nil {
		return nil, errHandshakeFormat
	}
	if len(b) < 3 {
		return nil, errHandshakeFormat
	}
	_ = b[2]
	h.cipherSuite = uint16(b[0])<<8 | uint16(b[1])
	h.compMethod = b[2]
	if h.raw, b = split2(b[3:]); b == nil {
		return nil, errHandshakeFormat
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
		return nil, errHandshakeFormat
	}
	_ = b[1]
	h := &helloVerifyRequest{
		ver: uint16(b[0])<<8 | uint16(b[1]),
	}
	if h.cookie, b = split(b[2:]); b == nil {
		return nil, errHandshakeFormat
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
		return nil, errHandshakeFormat
	}
	var v []byte
	c := &certificate{}
	for len(b) > 0 {
		if v, b = split3(b); b == nil {
			return nil, errHandshakeFormat
		}
		cert, err := x509.ParseCertificate(v)
		if err != nil {
			return nil, err
		}
		switch c := cert.PublicKey.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
		default:
			return nil, fmt.Errorf("dtls: unsupported type of certificate's public key: %T", c)
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
		return nil, errServerKeyExchange
	}
	_ = b[2]
	if b[0] != 3 {
		return nil, errServerKeyExchange
	}
	e := &serverKeyExchange{
		curve: uint16(b[1])<<8 | uint16(b[2]),
	}
	if e.pub, b = split(b[3:]); b == nil {
		return nil, errServerKeyExchange
	}
	if e.sign, b = split2(b); b == nil {
		return nil, errServerKeyExchange
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
	pub []byte
}

func parseClientKeyExchange(b []byte) (*clientKeyExchange, error) {
	e := &clientKeyExchange{}
	if e.pub, b = split(b); b == nil {
		return nil, errServerKeyExchange
	}
	return e, nil
}

func (e *clientKeyExchange) marshal(b []byte) []byte {
	return pack(b, e.pub, nil)
}

type certificateVerify struct {
	sign []byte
}

func parseCertificateVerify(b []byte) (*certificateVerify, error) {
	e := &certificateVerify{}
	if e.sign, b = split2(b); b == nil {
		return nil, errServerKeyExchange
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
		return nil, errServerKeyExchange
	}
	if r.names, b = split2(b); b == nil {
		return nil, errServerKeyExchange
	}
	return r, nil
}

func (r *certificateRequest) marshal(b []byte) []byte {
	b = pack(b, r.types, nil)
	return pack2(b, r.names, nil)
}
