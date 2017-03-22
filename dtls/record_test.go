package dtls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestClientHello(t *testing.T) {
	b, _ := hex.DecodeString("16feff0000000000000000009a0100008e000000000000008efefd9022059c50b987e4ba5d1d4cee973546184fe822c1bdadb140338fcf5aab651e00000022c02bc02f009ecca9cca8cc14cc13c009c0130033c00ac0140039009c002f0035000a01000042ff010001000017000000230000000d00140012040308040401050308050501080606010201000e000700040002000100000b00020100000a00080006001d00170018")
	r, _, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.typ != recordHandshake || r.ver != VersionDTLS10 || r.epoch != 0 || r.seq != 0 || len(r.raw) != 154 {
		t.Fatalf("record: %#v", r)
	}
	h, err := parseHandshake(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.typ != handshakeClientHello || h.seq != 0 || h.off != 0 || h.len != 142 || len(h.raw) != 142 {
		t.Fatalf("handshake: %#v", r)
	}
	m, err := parseClientHello(h.raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.ver != VersionDTLS12 || len(m.random) != 32 || len(m.sessionID) != 0 || len(m.cookie) != 0 || len(m.cipherSuites) != 17 || len(m.compMethods) != 1 || len(m.raw) != 66 {
		t.Fatalf("client hello: %#v", r)
	}
	e, err := parseExtensions(m.raw)
	if err != nil {
		t.Fatal(err)
	}
	if !e.renegotiationSupported || len(e.renegotiationInfo) != 0 || len(e.srtpProtectionProfiles) != 2 || len(e.srtpMasterKeyIdentifier) != 0 || !e.extendedMasterSecret || !e.sessionTicket || len(e.signatureAlgorithms) != 9 || len(e.supportedPoints) != 1 || len(e.supportedCurves) != 3 {
		t.Fatalf("extensions: %#v", e)
	}
	r.payload, h.message, m.extensions = h, m, e
	r.raw, h.raw, m.raw = nil, nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
	}
}

func TestServerHello(t *testing.T) {
	b, _ := hex.DecodeString("16feff0000000000000009004e020000420000000000000042feff5a646f92314ea551cac08a21e7025a6b1302c7543b87b7dbdb52df09ac33e60300c01300001aff0100010000230000000e00050002000100000b000403000102")
	r, _, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHandshake(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.typ != handshakeServerHello || h.seq != 0 || h.off != 0 || h.len != 66 || len(h.raw) != 66 {
		t.Fatalf("handshake: %#v", h)
	}
	m, err := parseServerHello(h.raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.ver != VersionDTLS10 || len(m.random) != 32 || len(m.sessionID) != 0 || m.cipherSuite == 0 || m.compMethod != 0 || len(m.raw) != 26 {
		t.Fatalf("server hello: %#v", m)
	}
	e, err := parseExtensions(m.raw)
	if err != nil {
		t.Fatal(err)
	}
	if !e.renegotiationSupported || len(e.renegotiationInfo) != 0 || len(e.srtpProtectionProfiles) != 1 || len(e.srtpMasterKeyIdentifier) != 0 || e.extendedMasterSecret || !e.sessionTicket || len(e.signatureAlgorithms) != 0 || len(e.supportedPoints) != 3 || len(e.supportedCurves) != 0 {
		t.Fatalf("extensions: %#v", e)
	}
	r.payload, h.message, m.extensions = h, m, e
	r.raw, h.raw, m.raw = nil, nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
	}
}

func TestHelloVerifyRequest(t *testing.T) {
	b, _ := hex.DecodeString("16feff00000000000000000023030000170000000000000017feff1479ce11df12ab98cf9f87df95cd4554c26b6f3701")
	r, _, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHandshake(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseHelloVerifyRequest(h.raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.ver != VersionDTLS10 || len(m.cookie) != 20 {
		t.Fatalf("hello verify request: %#v", m)
	}
	r.payload, h.message = h, m
	r.raw, h.raw = nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
	}
}

func TestServerKeyExchange(t *testing.T) {
	d := &handshakeTransport{}
	d.in.seq = 2
	for _, it := range []string{
		"16feff000000000000000e00f20c00014700020000000000e60300174104cbaecd1b61e5a9480a702836f0a8a0a44f8f0c88e8009f45acfacf654d8e47fe4005cd215f9a5c38cb8ad5f5d528bea7ec2ff3f09633c57941287fee09e5effd01003738960f95e19967fbf1e36d8082ae9c8311126a0f695134feeb06ab205b34e201cf59bb07b1e57bcf809c7452f5824854c0c51a5471f93d03430bdc61a5a21b45bde88b967e22ce5549bed6bce8c3696fa5f9c7f4662eaa039cd904a6e9e6aaf4618db14b46f35057a54ec04121c5ba9b4c2d1de61d588fe2ddd04913f9f880f5fe3cebb26c49647d2a5c898fabf34edfea5c4cc9b4991c1de62be4dc3aa8",
		"16feff000000000000000f006d0c00014700020000e60000611b89d720a8722ced8270a728a34fb49d01b3ae61fbff3e85bb6f15fb09a4d406e9146f5122d51c9beee570e999db2238c2e55df2a801f355bf73d02a1e154b2f859a3579e5a3927a16c0d0794780db346381342cc72ddb7f6ab75cff18533c9ed7",
	} {
		b, _ := hex.DecodeString(it)
		r, _, _ := parseRecord(b)
		if err := d.parse(r.raw); err != nil {
			t.Fatal(err)
		}
	}
	h := d.next()
	if h == nil {
		t.Fatal("no message")
	}
	m, err := parseServerKeyExchange(h.raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.curve != secp256r1 || len(m.pub) != 65 || len(m.sign) != 256 {
		t.Fatalf("server key exchange: %#v", m)
	}
}

func TestCertificateRequest(t *testing.T) {
	b, _ := hex.DecodeString("16feff000000000000001000120d0000060003000000000006030102400000")
	r, _, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHandshake(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseCertificateRequest(h.raw)
	if len(m.types) != 3 {
		t.Fatalf("certificate request: %#v", m)
	}
	r.payload, h.message = h, m
	r.raw, h.raw = nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
	}
}

func TestCertificate(t *testing.T) {
	b, _ := hex.DecodeString("16feff0000000000000005012c0b000120000100000000012000011d00011a308201163081bda0030201020209008b79549d52a904f3300a06082a8648ce3d0403023011310f300d06035504030c06576562525443301e170d3137303330363132303235385a170d3137303430363132303235385a3011310f300d06035504030c065765625254433059301306072a8648ce3d020106082a8648ce3d03010703420004a632caaa17d177a87147e9fe26eaf3c908b009af37791e1a40ab75233b214e6d25f50e4992c6cb5f87e4831b641e3ba3e8c7c36295255ee13bdef78361570f98300a06082a8648ce3d04030203480030450221009b2fc3ae418c397ea8e360233aac76516894ec2a5270dcf2ba3c918d06da23dd0220307d53e7a84cd276e5cfe63ebf9988befc5c072215179e5c465f5a5b0ea41aca")
	r, _, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHandshake(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseCertificate(h.raw)
	if len(m.cert) != 1 {
		t.Fatalf("certificate: %#v", m)
	}
	r.payload, h.message = h, m
	r.raw, h.raw = nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
	}
}

func TestClientKeyExchange(t *testing.T) {
	b, _ := hex.DecodeString("16feff0000000000000006004e1000004200020000000000424104da7b84688803e5a9a917bbd65d4a3b6f946a8bcd732823b633b1ad2941115332a3a495e3e2905ba3d52989fc55c80f8590c1483903be0b95a5708c9096c15111")
	r, _, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHandshake(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseClientKeyExchange(keyECDH, h.raw)
	if m.typ != keyECDH || len(m.pub) != 65 {
		t.Fatalf("client key exchange: %#v", m)
	}
	r.payload, h.message = h, m
	r.raw, h.raw = nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
	}
}

func TestCertificateVerify(t *testing.T) {
	b, _ := hex.DecodeString("16feff000000000000000700560f00004a000300000000004a00483046022100d9a23e63abafdcdf0206220bb4e421943ea7544e2a08d8092a1f24960637c6c9022100d68883e9bff213155097faf172bb2232a7b2f7a7ebd095ef98344daf9eaf9019")
	r, _, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHandshake(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseCertificateVerify(h.raw)
	if len(m.sign) != 72 {
		t.Fatalf("client key exchange: %#v", m)
	}
	r.payload, h.message = h, m
	r.raw, h.raw = nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
	}
}
