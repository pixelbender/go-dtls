package tls

import (
	"net"
	"hash"
)

type Conn struct {
	net.Conn
	tr     transport
	config *Config
}

func newConn(tr transport, config *Config) *Conn {
	if config == nil {
		config = defaultConfig
	}
	return &Conn{
		tr,
		tr,
		config,
	}
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

type transport interface {
	net.Conn
	SetVersion(ver uint16)
	SendAlert(alert uint8) error
	WriteRecord(typ uint8, data []byte) error
	WriteHandshake(m handshakeMessage) error
	ReadRecord() (uint8, []byte, error)
	ReadHandshake(expected ... handshakeMessage) (uint8, error)
	Next(spec *cipherSpec) transport
	Handshake() []byte
}

func newTransport(conn net.Conn, config *Config) (transport, error) {
	return &tcpTransport{
		Conn: conn,
		ver:  VersionTLS10,
	}, nil
}

type udpTransport struct {
	net.Conn
}

func (tr *udpTransport) SendAlert(alert uint8) error {
	return nil
	//return tr.WriteRecord(recordAlert, []byte{alertLevelError, alert})
}

func (tr *udpTransport) Close() error {
	// TODO: send alert only if handshake done
	tr.SendAlert(alertCloseNotify)
	return tr.Conn.Close()
}

type cipherSpec struct {
	incipher  cbcBlock
	inmac     hash.Hash
	outcipher cbcBlock
	outmac    hash.Hash
}
