package dtls

import (
	"crypto/x509"
	"errors"
)

var (
	errHandshakeFormat          = errors.New("dtls: handshake format error")
	errCertificateRequestFormat = errors.New("dtls: certificate_request format error")
	errClientHelloFormat        = errors.New("dtls: client_hello format error")
	errServerHelloFormat        = errors.New("dtls: server_hello format error")
	errHelloVerifyRequestFormat = errors.New("dtls: hello_verify_request format error")
	errCertificateFormat        = errors.New("dtls: certificate format error")
	errServerKeyExchangeFormat  = errors.New("dtls: server_key_exchange format error")
	errClientKeyExchangeFormat  = errors.New("dtls: client_key_exchange format error")
	errCertificateVerifyFormat  = errors.New("dtls: certificate_verify format error")

	errHandshakeSequence           = errors.New("dtls: handshake sequence error")
	errHandshakeMessageOutOfBounds = errors.New("dtls: handshake message is out of bounds")
	errHandshakeMessageTooBig      = errors.New("dtls: handshake message is too big")
	errHandshakeTimeout            = errors.New("dtls: handshake timeout")

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
