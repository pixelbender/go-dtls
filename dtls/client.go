package dtls

import (
	"errors"
	"net"
	"strings"
)

// Client returns a new DTLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, config *Config) *Conn {
	return &Conn{Conn: conn, config: config, isClient: true}
}

func clientHandshake(conn *Conn) (err error) {
	c := conn.config
	if c == nil {
		c = defaultConfig()
	}
	if len(c.ServerName) == 0 && !c.InsecureSkipVerify {
		return errors.New("dtls: either ServerName or InsecureSkipVerify must be specified in the dtls.Config")
	}
	enc := &handshakeEncoder{
		sender: &conn.sender,
		ver:    VersionDTLS10,
		mtu:    c.mtu(),
	}
	//dec := &handshakeDecoder{
	//	receiver: &conn.receiver,
	//}
	hello := &clientHello{
		Version:            c.maxVersion(),
		Random:             c.rand(),
		CompressionMethods: []uint8{compressionNone},
		CipherSuites:       defaultCipherSuites(),
		Extensions: map[uint16]Extension{
			extRenegotiationInfo:    renegotiationInfo(),
			extExtendedMasterSecret: nil,
			extSignatureAlgorithms:  signatureAlgorithmsExtension(supportedSignatureAlgorithms),
			extSupportedPoints:      pointFormatsExtension(supportedPointFormats),
			extSupportedGroups:      groupsExtension(supportedEllipticCurves),
		},
	}
	if len(c.ServerName) != 0 {
		hello.Extensions[extSessionTicket] = serverNamesExtension(c.ServerName)
	}
	if !c.SessionTicketsDisabled {
		hello.Extensions[extSessionTicket] = nil
	}
	enc.WriteMessage(typeClientHello, hello)
	if _, err = enc.WriteTo(conn.Conn); err != nil {
		return err
	}

	// todo timeout and retransmit
	//dec.ReadFrom(conn.Conn)
	return ErrNotImplemented
}

// hostnameInSNI converts name into an approriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See https://tools.ietf.org/html/rfc6066#section-3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
