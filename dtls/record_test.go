package dtls

import (
	"bytes"
	"encoding/hex"
	"testing"
	"crypto/x509"
)

func TestClientHello(t *testing.T) {
	b, _ := hex.DecodeString("16feff0000000000000000009a0100008e000000000000008efefd9022059c50b987e4ba5d1d4cee973546184fe822c1bdadb140338fcf5aab651e00000022c02bc02f009ecca9cca8cc14cc13c009c0130033c00ac0140039009c002f0035000a01000042ff010001000017000000230000000d00140012040308040401050308050501080606010201000e000700040002000100000b00020100000a00080006001d00170018")
	r, _, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.typ != recordHandshake || r.ver != VersionDTLS10 || r.epoch != 0 || r.seq != 0 || len(r.raw) != 154 {
		t.Fatal("record parse error:", r)
	}
	h, err := parseHandshake(r.raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.typ != handshakeClientHello || h.seq != 0 || h.off != 0 || h.len != 142 || len(h.raw) != 142 {
		t.Fatal("handshake parse error:", h)
	}
	m, err := parseClientHello(h.raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.ver != VersionDTLS12 || len(m.random) != 32 || len(m.sessionID) != 0 || len(m.cookie) != 0 || len(m.cipherSuites) != 17 || len(m.compMethods) != 1 || len(m.raw) != 66 {
		t.Fatal("client hello parse error:", m)
	}
	e, err := parseExtensions(m.raw)
	if err != nil {
		t.Fatal(err)
	}
	if !e.renegotiationSupported || len(e.renegotiationInfo) != 0 || len(e.srtpProtectionProfiles) != 2 || len(e.srtpMasterKeyIdentifier) != 0 || !e.extendedMasterSecret || !e.sessionTicket || len(e.signatureAlgorithms) != 9 || len(e.supportedPoints) != 1 || len(e.supportedCurves) != 3 {
		t.Fatal("extensions parse error:", e)
	}
	r.payload, h.message, m.extensions = h, m, e
	r.raw, h.raw, m.raw = nil, nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal error: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
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
		t.Fatal("handshake parse error:", h)
	}
	m, err := parseServerHello(h.raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.ver != VersionDTLS10 || len(m.random) != 32 || len(m.sessionID) != 0 || m.cipherSuite == 0 || m.compMethod != 0 || len(m.raw) != 26 {
		t.Fatal("wrong server hello:", m)
	}
	e, err := parseExtensions(m.raw)
	if err != nil {
		t.Fatal(err)
	}
	if !e.renegotiationSupported || len(e.renegotiationInfo) != 0 || len(e.srtpProtectionProfiles) != 1 || len(e.srtpMasterKeyIdentifier) != 0 || e.extendedMasterSecret || !e.sessionTicket || len(e.signatureAlgorithms) != 0 || len(e.supportedPoints) != 3 || len(e.supportedCurves) != 0 {
		t.Fatal("extensions parse error:", e)
	}
	r.payload, h.message, m.extensions = h, m, e
	r.raw, h.raw, m.raw = nil, nil, nil
	if p := r.marshal(nil); !bytes.Equal(b, p) {
		t.Fatalf("marshal error: \n%sexpected:\n%s", hex.Dump(p), hex.Dump(b))
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
		t.Fatalf("wrong hello verify request: %#v", m)
	}
}

func TestServerKeyExchange(t *testing.T) {
	d := &defrag{seq:2}
	for _, it := range []string{
		"16feff000000000000000e00f20c00014700020000000000e60300174104cbaecd1b61e5a9480a702836f0a8a0a44f8f0c88e8009f45acfacf654d8e47fe4005cd215f9a5c38cb8ad5f5d528bea7ec2ff3f09633c57941287fee09e5effd01003738960f95e19967fbf1e36d8082ae9c8311126a0f695134feeb06ab205b34e201cf59bb07b1e57bcf809c7452f5824854c0c51a5471f93d03430bdc61a5a21b45bde88b967e22ce5549bed6bce8c3696fa5f9c7f4662eaa039cd904a6e9e6aaf4618db14b46f35057a54ec04121c5ba9b4c2d1de61d588fe2ddd04913f9f880f5fe3cebb26c49647d2a5c898fabf34edfea5c4cc9b4991c1de62be4dc3aa8",
		"16feff000000000000000f006d0c00014700020000e60000611b89d720a8722ced8270a728a34fb49d01b3ae61fbff3e85bb6f15fb09a4d406e9146f5122d51c9beee570e999db2238c2e55df2a801f355bf73d02a1e154b2f859a3579e5a3927a16c0d0794780db346381342cc72ddb7f6ab75cff18533c9ed7",
	} {
		b, _ := hex.DecodeString(it)
		r, _, _ := parseRecord(b)
		d.parse(r.raw)
	}
	h := d.read()
	if h == nil {
		t.Fatal("no message")
	}
	m, err := parseServerKeyExchange(h.raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.curve != secp256r1 || len(m.pub) != 65 || len(m.sign) != 256 {
		t.Fatalf("wrong server key exchange: %#v", m)
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
		t.Fatalf("wrong certificate request: %#v", m)
	}
}

func TestHandshakeDefrag(t *testing.T) {
	frag := []string{
		"0b0002c700010000000000e60002c40002c1308202bd308201a5a003020102020100300d06092a864886f70d01010b05003022310b30090603550406130253453113301106035504030c0a4f70656e576562525443301e170d3137303330373132303235355a170d3138303330373132303235355a3022310b30090603550406130253453113301106035504030c0a4f70656e57656252544330820122300d06092a864886f70d01010105000382010f003082010a0282010100c2717a632ea4618e599ed6173dfafef22b4f8df27120e30978052c3532c41532ef7466cdf1fe70f6d0554069cb0dfec3ac99f93fabece26a",
		"0b0002c700010000e60000e7bb9fcefdae4197cee480c5dd0aa76ca2a9ae85287176180778ed7ce4b9c10bf3ee6426827cb4f4c933c6dd9c4e94dd43aa59d7c60a8a33db961a6dba5243de7ddeab2d9f13ed74a6c0259aa4358e8b25632a5f11e9692118ed1f084fb6953c9a1507825d919394c438cf277c149488c0628e6e3ddf2c1de4a4570b711cc51a6e0747e9aea0fc4687eeb10f45945eee41b147a0d697a825e3817e6b7d0a0ec5bd382c60e0f7c1ef1acb820ed28fdb2c5fa5abb1c8d5cddf9bf3f4309687baec0b2cb97cbf62f22fb30203010001300d06092a864886f70d01010b0500038201010061aa714fdc32",
		"0b0002c700010001cd0000e76b9a4b20a46e7264713326d9f4e3e5ca6b972daa4bdf318fc3e9c6b1de1b1f136272b6768ca74d49c7a1ea1296244e4f5a6b01e8938106b8d80fa43ebe0794c9d81c35d65cb62f40754e7a0d2d1ccd46fe5d79670be3c9b9c1fc30245542557f39222bec1a688445ff0f74015ecb7b4cfebc60916a48b48415d064c873fe68838d1cb7f00ecd8b3a0b9069c8a820ce75f7675275cafc50e30cab3c97400cef81475b984ec1f71676e55a6275a919f2a3d3e6d6da23a2eb91442693796e1ab69143700b7bcfa41cec8f5a0ce1ae15bbc671be681308e4f0f40d82deafbdb818d1eac53fa1f57c91",
		"0b0002c700010002b4000013bfd8f25c142f1d8416053b375e9ef44fbd06fd",
	}
	for _, seq := range [][]int{
		{0, 1, 2, 3},
		{3, 2, 1, 0},
		{2, 0, 1, 0, 2, 0, 3},
		{0, 1, 2, 1, 0, 1, 3},
	} {
		d := &defrag{seq: 1}
		for _, i := range seq {
			b, _ := hex.DecodeString(frag[i])
			if d.parse(b) != nil {
				continue
			}
		}
		h := d.read()
		if h == nil || d.seq != 2 {
			t.Fatal("defragmentation error:", seq)
		}
		cert, err := parseCertificate(h.raw)
		if err != nil {
			t.Fatal("certificate parse error:", err)
		}
		if len(cert) == 0 {
			t.Fatal("no certificate")
		}
		for _, it := range cert {
			if _, err := x509.ParseCertificate(it); err != nil {
				t.Fatal(err)
			}
		}
	}
}

/*
func TestServerKeyExchange(t *testing.T) {
	frag := []string{
		"0c00014700020000000000e60300174104cbaecd1b61e5a9480a702836f0a8a0a44f8f0c88e8009f45acfacf654d8e47fe4005cd215f9a5c38cb8ad5f5d528bea7ec2ff3f09633c57941287fee09e5effd01003738960f95e19967fbf1e36d8082ae9c8311126a0f695134feeb06ab205b34e201cf59bb07b1e57bcf809c7452f5824854c0c51a5471f93d03430bdc61a5a21b45bde88b967e22ce5549bed6bce8c3696fa5f9c7f4662eaa039cd904a6e9e6aaf4618db14b46f35057a54ec04121c5ba9b4c2d1de61d588fe2ddd04913f9f880f5fe3cebb26c49647d2a5c898fabf34edfea5c4cc9b4991c1de62be4dc3aa8",
		"0c00014700020000e60000611b89d720a8722ced8270a728a34fb49d01b3ae61fbff3e85bb6f15fb09a4d406e9146f5122d51c9beee570e999db2238c2e55df2a801f355bf73d02a1e154b2f859a3579e5a3927a16c0d0794780db346381342cc72ddb7f6ab75cff18533c9ed7",
	}
	d := &defrag{seq: 2}
	var m *serverKeyExchange
	for _, it := range frag {
		b, _ := hex.DecodeString(it)
		if h, _ := d.Parse(b); h != nil {
			m, _ = parseServerKeyExchange(h.raw)
		}
	}
	if m != nil {

	}
}

func _TestClientCert(t *testing.T) {
	b, _ := hex.DecodeString("16feff0000000000000005012c0b000120000100000000012000011d00011a308201163081bda0030201020209008b79549d52a904f3300a06082a8648ce3d0403023011310f300d06035504030c06576562525443301e170d3137303330363132303235385a170d3137303430363132303235385a3011310f300d06035504030c065765625254433059301306072a8648ce3d020106082a8648ce3d03010703420004a632caaa17d177a87147e9fe26eaf3c908b009af37791e1a40ab75233b214e6d25f50e4992c6cb5f87e4831b641e3ba3e8c7c36295255ee13bdef78361570f98300a06082a8648ce3d04030203480030450221009b2fc3ae418c397ea8e360233aac76516894ec2a5270dcf2ba3c918d06da23dd0220307d53e7a84cd276e5cfe63ebf9988befc5c072215179e5c465f5a5b0ea41aca16feff0000000000000006004e1000004200020000000000424104da7b84688803e5a9a917bbd65d4a3b6f946a8bcd732823b633b1ad2941115332a3a495e3e2905ba3d52989fc55c80f8590c1483903be0b95a5708c9096c1511116feff000000000000000700560f00004a000300000000004a00483046022100d9a23e63abafdcdf0206220bb4e421943ea7544e2a08d8092a1f24960637c6c9022100d68883e9bff213155097faf172bb2232a7b2f7a7ebd095ef98344daf9eaf901914feff0000000000000008000101")
	var r *record
	var err error
	for len(b) > 0 {
		t.Logf("%#v", len(b))
		if r, b, err = parseRecord(b); err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v", r)
		if r.typ == recordHandshake {
			h, err := parseHandshake(r.raw)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("\t%#v", h)
		}
	}
}
*/

func _TestHandshakeFlight(t *testing.T) {
	f := &flight{}
	for _, mtu := range []int{1024, 512, 256, 128, 64, 32} {
		f.prepare(mtu, &record{
			typ: recordHandshake,
			ver: VersionDTLS10,
		}, &handshake{
			typ: handshakeClientHello,
			message: &clientHello{
				ver:    VersionDTLS10,
				random: make([]byte, 32),
				extensions: &extensions{
					renegotiationSupported: true,
					srtpProtectionProfiles: srtpSupportedProtectionProfiles,
					extendedMasterSecret:   true,
					sessionTicket:          true,
					signatureAlgorithms:    supportedSignatureAlgorithms,
					supportedPoints:        supportedPointFormats,
					supportedCurves:        supportedCurves,
				},
			},
		})
		b := f.raw
		d := &defrag{}
		for len(b) > 0 {
			r, next, err := parseRecord(b)
			if err != nil {
				t.Fatal("record parse error:", err)
			}
			err = d.parse(r.raw)
			if err != nil {
				t.Fatal("handshake parse error:",err)
			}
			b = next
		}
		h := d.read()
		if h == nil {
			t.Fatal("no handshake message")
		}
		_, err := parseClientHello(h.raw)
		if err != nil {
			t.Fatal(err)
		}
	}
}
