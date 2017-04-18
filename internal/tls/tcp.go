package tls

import (
	"io"
	"net"
	"crypto/rand"
	"errors"
	"log"
)

type tcpTransport struct {
	net.Conn
	ver  uint16
	spec *cipherSpec

	// log stores handshake log
	log  []byte
	seq  seq
}

func (tr *tcpTransport) SetVersion(ver uint16) {
	tr.ver = ver
}

func (tr *tcpTransport) Handshake() []byte {
	return tr.log
}

func (tr *tcpTransport) SendAlert(alert uint8) error {
	return tr.WriteRecord(recordAlert, []byte{alertLevelError, alert})
}

func (tr *tcpTransport) WriteRecord(typ uint8, data []byte) error {
	b := make([]byte, 0, 1024) // TODO: buffer pool

	v, b := grow(b, 3)
	_ = v[2]
	v[0] = typ
	v[1], v[2] = uint8(tr.ver>>8), uint8(tr.ver)

	/*
	tls1.2+ explicitIVLen = cbc.BlockSize()
	aead? = explicitIVLen = c.explicitNonceLen()

	 */

	if tr.spec != nil {
		cipher := tr.spec.outcipher
		h := tr.spec.outmac
		h.Reset()
		h.Write(tr.seq[0:])
		h.Write(v)

		var iv []byte
		iv, b = grow(b, cipher.BlockSize())
		rand.Reader.Read(iv) // TODO: errors...
		cipher.SetIV(iv)


		pos := len(b)
		b = pack2(b, data, nil)
		log.Printf("hs size = %d", len(b) - pos)
		h.Write(b[pos:])

		z := len(b)
		b = h.Sum(b)

		// [0..4][iv 16].[data 18][mac 20]

		size := cipher.BlockSize()
		over := (len(b) - pos) % size

		log.Printf("iv size = %d, bsize = %d, mac = %d, dsize = %d, over = %d", len(iv), size, len(b) -z, len(b) - pos, over)

		l := size - over
		for i := 0; i < l; i++ {
			b = append(b, uint8(l-1))
		}
		cipher.CryptBlocks(b[pos:], b[pos:])

		n := len(b) - 5
		b[3] = byte(n >> 8)
		b[4] = byte(n)

	} else {
		b = pack2(b, data, nil)
	}

	tr.seq.inc()
	_, err := tr.Write(b)
	return err
}

func (tr *tcpTransport) WriteHandshake(m handshakeMessage) error {
	// TODO: check mtu
	b := make([]byte, 0, 1024) // TODO: buffer pool

	v, b := grow(b, 1)
	v[0] = m.typ()
	b = pack3(b, nil, m)

	tr.log = append(tr.log, b...)
	log.Printf("log += %d (%s)", len(b), handshakeText(m.typ()))
	return tr.WriteRecord(recordHandshake, b)
}

func (tr *tcpTransport) ReadRecord() (uint8, []byte, error) {
	b := make([]byte, 5)
	_, err := io.ReadFull(tr.Conn, b[:5])
	if err != nil {
		return 0, nil, err
	}
	_ = b[4]
	//ver := uint16(b[1])<<8 | uint16(b[2])
	// TODO: check version
	l := uint16(b[3])<<8 | uint16(b[4])

	p := make([]byte, l)
	_, err = io.ReadFull(tr.Conn, p)
	if err != nil {
		return 0, nil, err
	}
	return b[0], p, nil
}

func (tr *tcpTransport) ReadHandshake(expected ... handshakeMessage) (uint8, error) {
	typ, b, err := tr.ReadRecord()
	if err != nil {
		return 0, err
	}
	if typ == recordAlert {
		_, alert, err := parseAlert(b)
		if err != nil {
			return 0, err
		}
		// TODO: skip warnings?
		return 0, errAlert(alert)
	}
	if typ != recordHandshake {
		return 0, errors.New("tls: unexpected record")
	}

	if len(b) < 4 {
		return 0, errors.New("tls: handshake format error")
	}

	tr.log = append(tr.log, b...)
	log.Printf("log += %d (%s)", len(b), handshakeText(b[0]))
	typ = b[0]
	v, _ := split3(b[1:])
	if v == nil {
		return 0, errors.New("tls: handshake format error")
	}
	for _, it := range expected {
		if it.typ() == typ && it.unmarshal(v) {
			return typ, nil
		}
	}

	tr.SendAlert(alertUnexpectedMessage)

	return 0, &errHandshakeUnexpected{typ, expected[0].typ()}
}

func (tr *tcpTransport) Next(spec *cipherSpec) transport {
	return &tcpTransport{
		Conn: tr.Conn,
		ver:  tr.ver,
		spec: spec,
	}
}
