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
