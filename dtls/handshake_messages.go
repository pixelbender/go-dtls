package dtls

type clientHelloMsg struct {
	raw                 []byte
	vers                uint16
	random              []byte
	sessionId           []byte
	cipherSuites        []uint16
	compressionMethods  []uint8
	nextProtoNeg        bool
	serverName          string
	ocspStapling        bool
	scts                bool
	supportedCurves     []CurveID
	supportedPoints     []uint8
	ticketSupported     bool
	sessionTicket       []uint8
	signatureAndHashes  []signatureAndHash
	secureRenegotiation bool
	alpnProtocols       []string
}

func (m *clientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 2 + len(m.cipherSuites)*2 + 1 + len(m.compressionMethods)
	numExtensions := 0
	extensionsLength := 0
	if m.nextProtoNeg {
		numExtensions++
	}
	if m.ocspStapling {
		extensionsLength += 1 + 2 + 2
		numExtensions++
	}
	if len(m.serverName) > 0 {
		extensionsLength += 5 + len(m.serverName)
		numExtensions++
	}
	if len(m.supportedCurves) > 0 {
		extensionsLength += 2 + 2*len(m.supportedCurves)
		numExtensions++
	}
	if len(m.supportedPoints) > 0 {
		extensionsLength += 1 + len(m.supportedPoints)
		numExtensions++
	}
	if m.ticketSupported {
		extensionsLength += len(m.sessionTicket)
		numExtensions++
	}
	if len(m.signatureAndHashes) > 0 {
		extensionsLength += 2 + 2*len(m.signatureAndHashes)
		numExtensions++
	}
	if m.secureRenegotiation {
		extensionsLength += 1
		numExtensions++
	}
	if len(m.alpnProtocols) > 0 {
		extensionsLength += 2
		for _, s := range m.alpnProtocols {
			if l := len(s); l == 0 || l > 255 {
				panic("invalid ALPN protocol")
			}
			extensionsLength++
			extensionsLength += len(s)
		}
		numExtensions++
	}
	if m.scts {
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	y := x[39+len(m.sessionId):]
	y[0] = uint8(len(m.cipherSuites) >> 7)
	y[1] = uint8(len(m.cipherSuites) << 1)
	for i, suite := range m.cipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.cipherSuites)*2:]
	z[0] = uint8(len(m.compressionMethods))
	copy(z[1:], m.compressionMethods)

	z = z[1+len(m.compressionMethods):]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.nextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		// The length is always 0
		z = z[4:]
	}
	if len(m.serverName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName & 0xff)
		l := len(m.serverName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		z[0] = byte((len(m.serverName) + 3) >> 8)
		z[1] = byte(len(m.serverName) + 3)
		z[3] = byte(len(m.serverName) >> 8)
		z[4] = byte(len(m.serverName))
		copy(z[5:], []byte(m.serverName))
		z = z[l:]
	}
	if m.ocspStapling {
		// RFC 4366, section 3.6
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z[2] = 0
		z[3] = 5
		z[4] = 1 // OCSP type
		// Two zero valued uint16s for the two lengths.
		z = z[9:]
	}
	if len(m.supportedCurves) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.1
		z[0] = byte(extensionSupportedCurves >> 8)
		z[1] = byte(extensionSupportedCurves)
		l := 2 + 2*len(m.supportedCurves)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		z = z[6:]
		for _, curve := range m.supportedCurves {
			z[0] = byte(curve >> 8)
			z[1] = byte(curve)
			z = z[2:]
		}
	}
	if len(m.supportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.2
		z[0] = byte(extensionSupportedPoints >> 8)
		z[1] = byte(extensionSupportedPoints)
		l := 1 + len(m.supportedPoints)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l--
		z[4] = byte(l)
		z = z[5:]
		for _, pointFormat := range m.supportedPoints {
			z[0] = byte(pointFormat)
			z = z[1:]
		}
	}
	if m.ticketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		l := len(m.sessionTicket)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]
		copy(z, m.sessionTicket)
		z = z[len(m.sessionTicket):]
	}
	if len(m.signatureAndHashes) > 0 {
		// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		z[0] = byte(extensionSignatureAlgorithms >> 8)
		z[1] = byte(extensionSignatureAlgorithms)
		l := 2 + 2*len(m.signatureAndHashes)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l -= 2
		z[0] = byte(l >> 8)
		z[1] = byte(l)
		z = z[2:]
		for _, sigAndHash := range m.signatureAndHashes {
			z[0] = sigAndHash.hash
			z[1] = sigAndHash.signature
			z = z[2:]
		}
	}
	if m.secureRenegotiation {
		z[0] = byte(extensionRenegotiationInfo >> 8)
		z[1] = byte(extensionRenegotiationInfo & 0xff)
		z[2] = 0
		z[3] = 1
		z = z[5:]
	}
	if len(m.alpnProtocols) > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		lengths := z[2:]
		z = z[6:]

		stringsLength := 0
		for _, s := range m.alpnProtocols {
			l := len(s)
			z[0] = byte(l)
			copy(z[1:], s)
			z = z[1+l:]
			stringsLength += 1 + l
		}

		lengths[2] = byte(stringsLength >> 8)
		lengths[3] = byte(stringsLength)
		stringsLength += 2
		lengths[0] = byte(stringsLength >> 8)
		lengths[1] = byte(stringsLength)
	}
	if m.scts {
		// https://tools.ietf.org/html/rfc6962#section-3.3.1
		z[0] = byte(extensionSCT >> 8)
		z[1] = byte(extensionSCT)
		// zero uint16 for the zero-length extension_data
		z = z[4:]
	}

	m.raw = x

	return x
}

type serverHelloMsg struct {
	raw                 []byte
	vers                uint16
	random              []byte
	sessionId           []byte
	cipherSuite         uint16
	compressionMethod   uint8
	nextProtoNeg        bool
	nextProtos          []string
	ocspStapling        bool
	scts                [][]byte
	ticketSupported     bool
	secureRenegotiation bool
	alpnProtocol        string
}

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte
}
