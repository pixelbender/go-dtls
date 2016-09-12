package dtls

import (
	"io"
)

const (
	typeHelloRequest       uint8 = 0
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeHelloVerifyRequest uint8 = 3
	typeNewSessionTicket   uint8 = 4
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
	typeCertificateStatus  uint8 = 22
)

type handshakeMsg interface {
	Marshal(w writer)
	Unmarshal(r reader) error
}

func newMessage(typ uint8) handshakeMsg {
	switch typ {
	case typeClientHello:
		return new(clientHello)
	case typeServerHello:
		return new(serverHello)
	case typeCertificate:
		return new(certificate)
	}
	return nil
}

type clientHello struct {
	Version            uint16
	Random             io.Reader
	RandomBytes        []uint8
	Session            []uint8
	Cookie             []uint8
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         map[uint16]Extension
}

func (m *clientHello) Marshal(w writer) {
	b := w.Next(34)
	be.PutUint16(b, m.Version)
	if m.RandomBytes != nil {
		copy(b[2:], m.RandomBytes)
	} else {
		m.RandomBytes = b[2:]
		m.Random.Read(m.RandomBytes)
	}
	putSlice8(w, m.Session)
	putSlice8(w, m.Cookie)
	putSlice16(w, m.CipherSuites)
	putSlice8(w, m.CompressionMethods)
	putExtensions(w, m.Extensions)
}

func (m *clientHello) Unmarshal(r reader) (err error) {
	var b []byte
	b, err = r.Next(34)
	if err == nil {
		m.Version = be.Uint16(b)
		m.RandomBytes = b[2:34]
		m.Session, err = getSlice8(r)
	}
	if err == nil {
		m.Cookie, err = getSlice8(r)
	}
	if err == nil {
		m.CipherSuites, err = getSlice16(r)
	}
	if err == nil {
		m.CompressionMethods, err = getSlice8(r)
	}
	if err == nil && r.Len() > 0 {
		m.Extensions, err = getExtensions(r)
	}
	return
}

type serverHello struct {
	Version           uint16
	Random            io.Reader
	RandomBytes       []uint8
	Session           []uint8
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        map[uint16]Extension
}

func (m *serverHello) Marshal(w writer) {
	b := w.Next(34)
	be.PutUint16(b, m.Version)
	if m.RandomBytes != nil {
		copy(b[2:], m.RandomBytes)
	} else {
		m.RandomBytes = b[2:]
		m.Random.Read(m.RandomBytes)
	}
	putSlice8(w, m.Session)
	b = w.Next(3)
	be.PutUint16(b, m.CipherSuite)
	b[2] = m.CompressionMethod
	putExtensions(w, m.Extensions)
}

func (m *serverHello) Unmarshal(r reader) (err error) {
	var b []byte
	b, err = r.Next(34)
	if err == nil {
		m.Version = be.Uint16(b)
		m.RandomBytes = b[2:34]
		m.Session, err = getSlice8(r)
	}
	b, err = r.Next(3)
	if err == nil {
		m.CipherSuite = be.Uint16(b)
		m.CompressionMethod = b[2]
		if r.Len() > 0 {
			m.Extensions, err = getExtensions(r)
		}
	}
	return
}

type Extension interface {
	Bytes() []byte
}

type rawExtension []byte

func (e rawExtension) Bytes() []byte {
	return []byte(e)
}

type certificate struct {
	Certificates [][]byte
}

func (c *certificate) Marshal(w writer) {
	for _, it := range c.Certificates {
		b := w.Next(3)
		putInt24(b, len(it))
		w.Write(it)
	}
}

func (c *certificate) Unmarshal(r reader) (err error) {
	var b []byte
	for r.Len() > 3 {
		if b, err = r.Next(3); err != nil {
			return
		}
		if b, err = r.Next(getInt24(b)); err != nil {
			return
		}
		c.Certificates = append(c.Certificates, b)
	}
	return
}

type signatureAlgorithmsExtension []signatureAlgorithm

func (e signatureAlgorithmsExtension) Bytes() []byte {
	v := []signatureAlgorithm(e)
	n := len(v) << 1
	b := make([]byte, 2+n)
	be.PutUint16(b, uint16(n))
	for i, it := range v {
		b[i<<1] = it.hash
		b[i<<1+1] = it.sign
	}
	return b
}

func groupsExtension(v []uint16) Extension {
	n := len(v) << 1
	b := make([]byte, 2+n)
	be.PutUint16(b, uint16(n))
	for i, it := range v {
		be.PutUint16(b[i<<1:], it)
	}
	return rawExtension(b)
}

func pointFormatsExtension(v []uint8) Extension {
	n := len(v)
	b := make([]byte, 1+n)
	b[0] = uint8(n)
	copy(b[1:], v)
	return rawExtension(b)
}

func serverNamesExtension(v string) Extension {
	n := len(v)
	b := make([]byte, 5+n)
	be.PutUint16(b, uint16(3+n))
	b[2] = 0
	be.PutUint16(b[3:], uint16(n))
	copy(b[5:], v)
	return rawExtension(b)
}

func renegotiationInfo() Extension {
	return rawExtension([]byte{0})
}

func sessionTicket() Extension {
	return nil
}
