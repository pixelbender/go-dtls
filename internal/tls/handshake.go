package tls

import (
	"crypto/x509"
	"strconv"
	"github.com/pkg/errors"
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

var handshakeTexts = map[uint8]string{
	handshakeClientHello:        "client hello",
	handshakeServerHello:        "server hello",
	handshakeHelloVerifyRequest: "hello verify request",
	handshakeCertificate:        "certificate",
	handshakeServerKeyExchange:  "server key exchange",
	handshakeCertificateRequest: "certificate request",
	handshakeServerHelloDone:    "server hello done",
	handshakeCertificateVerify:  "certificate verify",
	handshakeClientKeyExchange:  "client key exchange",
	handshakeFinished:           "finished",
}

func handshakeText(typ uint8) string {
	v, ok := handshakeTexts[typ]
	if !ok {
		v = "handshake(" + strconv.Itoa(int(typ)) + ")"
	}
	return v
}

type handshakeMessage interface {
	typ() uint8
	unmarshal(b []byte) bool
	marshal(b []byte) []byte
}

const compressionNone uint8 = 0

const (
	dtls10 uint16 = 0xfeff
	dtls12 uint16 = 0xfefd
)

type clientHello struct {
	ver                uint16
	random             []byte
	sessionID          []byte
	cookie             []byte
	cipherSuites       []uint16
	compressionMethods []uint8
	dtls               bool
	extensions
}

func (*clientHello) typ() uint8 {
	return handshakeClientHello
}

func (h *clientHello) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 34)
	_ = v[33]
	v[0], v[1] = uint8(h.ver>>8), uint8(h.ver)
	copy(v[2:], h.random)
	b = pack(b, h.sessionID, nil)
	if h.dtls {
		b = pack(b, h.cookie, nil)
	}
	n := len(h.cipherSuites) << 1
	v, b = grow(b, 2+n)
	_ = v[1]
	v[0], v[1], v = uint8(n>>8), uint8(n), v[2:]
	for _, s := range h.cipherSuites {
		_ = v[1]
		v[0], v[1], v = uint8(s>>8), uint8(s), v[2:]
	}
	b = pack(b, h.compressionMethods, nil)
	return pack2(b, nil, &h.extensions)
}

func (h *clientHello) unmarshal(b []byte) bool {
	if len(b) < 34 {
		return false
	}
	_ = b[33]
	h.ver = uint16(b[0])<<8 | uint16(b[1])
	h.random = b[2:34]
	var v []byte
	if h.sessionID, b = split(b[34:]); b == nil {
		return false
	}
	if h.dtls {
		if h.cookie, b = split(b); b == nil {
			return false
		}
	}
	if v, b = split2(b); b == nil {
		return false
	}
	h.cipherSuites = make([]uint16, len(v)>>1)
	for i := range h.cipherSuites {
		_ = v[1]
		h.cipherSuites[i], v = uint16(v[0])<<8|uint16(v[1]), v[2:]
	}
	if h.compressionMethods, b = split(b); b == nil {
		return false
	}
	ext, b := split2(b)
	if b == nil {
		return false
	}
	return h.extensions.unmarshal(ext)
}

type serverHello struct {
	ver         uint16
	random      []byte
	sessionID   []byte
	cipherSuite uint16
	compMethod  uint8
	extensions
}

func (*serverHello) typ() uint8 {
	return handshakeServerHello
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
	return pack2(b, nil, &h.extensions)
}

func (h *serverHello) unmarshal(b []byte) bool {
	if len(b) < 34 {
		return false
	}
	_ = b[33]
	h.ver = uint16(b[0])<<8 | uint16(b[1])
	h.random = b[2:34]
	if h.sessionID, b = split(b[34:]); b == nil {
		return false
	}
	if len(b) < 3 {
		return false
	}
	_ = b[2]
	h.cipherSuite = uint16(b[0])<<8 | uint16(b[1])
	h.compMethod = b[2]
	ext, b := split2(b[3:])
	if b == nil {
		return false
	}
	return h.extensions.unmarshal(ext)
}

type helloVerifyRequest struct {
	ver    uint16
	cookie []byte
}

func (*helloVerifyRequest) typ() uint8 {
	return handshakeHelloVerifyRequest
}

func (h *helloVerifyRequest) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 2)
	_ = v[1]
	v[0], v[1] = uint8(h.ver>>8), uint8(h.ver)
	return pack(b, h.cookie, nil)
}

func (h *helloVerifyRequest) unmarshal(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	_ = b[1]
	h.ver = uint16(b[0])<<8 | uint16(b[1])
	h.cookie, b = split(b[2:])
	return b != nil
}

type certificate struct {
	raw  [][]byte
	cert []*x509.Certificate
}

func (*certificate) typ() uint8 {
	return handshakeCertificate
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

func (c *certificate) unmarshal(b []byte) bool {
	if b, _ = split3(b); b == nil {
		return false
	}
	var v []byte
	for len(b) > 0 {
		if v, b = split3(b); b == nil {
			return false
		}
		cert, err := x509.ParseCertificate(v) // TODO: fixme error
		if err != nil {
			return false
		}
		c.raw = append(c.raw, v)
		c.cert = append(c.cert, cert)
	}
	return true
}

type serverKeyExchange struct {
	curve uint16
	pub   []byte
	sign  []byte
}

func (*serverKeyExchange) typ() uint8 {
	return handshakeServerKeyExchange
}

func (s *serverKeyExchange) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 3)
	_ = b[2]
	v[0], v[1], v[2] = 3, uint8(s.curve>>8), uint8(s.curve)
	b = pack(b, s.pub, nil)
	return pack2(b, s.sign, nil)
}

func (s *serverKeyExchange) unmarshal(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	_ = b[2]
	if b[0] != 3 {
		return false
	}
	s.curve = uint16(b[1])<<8 | uint16(b[2])
	if s.pub, b = split(b[3:]); b == nil {
		return false
	}
	s.sign, b = split2(b)
	return b != nil
}

type clientKeyExchange struct {
}

func (*clientKeyExchange) typ() uint8 {
	return handshakeClientKeyExchange
}

type clientKeyExchangeRSA struct {
	clientKeyExchange
	pub []byte
}

func (c *clientKeyExchangeRSA) marshal(b []byte) []byte {
	return pack2(b, c.pub, nil)
}

func (c *clientKeyExchangeRSA) unmarshal(b []byte) bool {
	c.pub, b = split2(b)
	return b != nil
}

type clientKeyExchangeDH struct {
	clientKeyExchange
	pub []byte
}

func (c *clientKeyExchangeDH) marshal(b []byte) []byte {
	return pack(b, c.pub, nil)
}

func (c *clientKeyExchangeDH) unmarshal(b []byte) bool {
	c.pub, b = split(b)
	return b != nil
}

type certificateVerify struct {
	sign []byte
}

func (*certificateVerify) typ() uint8 {
	return handshakeCertificateVerify
}

func (c *certificateVerify) marshal(b []byte) []byte {
	return pack2(b, c.sign, nil)
}

func (c *certificateVerify) unmarshal(b []byte) bool {
	c.sign, b = split2(b)
	return b != nil
}

type certificateRequest struct {
	types []uint8
	names []byte
}

func (*certificateRequest) typ() uint8 {
	return handshakeCertificateRequest
}

func (r *certificateRequest) marshal(b []byte) []byte {
	b = pack(b, r.types, nil)
	return pack2(b, r.names, nil)
}

func (r *certificateRequest) unmarshal(b []byte) bool {
	if r.types, b = split(b); b == nil {
		return false
	}
	r.names, b = split2(b)
	return b != nil
}

type serverHelloDone struct {
}

func (*serverHelloDone) typ() uint8 {
	return handshakeServerHelloDone
}

func (r *serverHelloDone) marshal(b []byte) []byte {
	return b
}

func (r *serverHelloDone) unmarshal(b []byte) bool {
	return b != nil
}

type finished struct {
	data []byte
}

func (*finished) typ() uint8 {
	return handshakeFinished
}

func (r *finished) marshal(b []byte) []byte {
	return append(b, r.data...)
}

func (r *finished) unmarshal(b []byte) bool {
	r.data = b
	return true
}

var (
	errUnsupportedKeyExchangeAlgorithm = errors.New("tls: unsupported key exchange algorithm")
)

type errHandshakeFormat uint8

func (e errHandshakeFormat) String() string {
	return "tls: " + handshakeText(uint8(e)) + " format error"
}

func (e errHandshakeFormat) Error() string {
	return e.String()
}

type errHandshakeUnexpected struct {
	got, want uint8
}

func (e errHandshakeUnexpected) String() string {
	return "tls: unexpected " + handshakeText(e.got) + ", want " + handshakeText(e.want)
}

func (e errHandshakeUnexpected) Error() string {
	return e.String()
}
