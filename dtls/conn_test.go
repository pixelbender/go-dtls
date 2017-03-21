package dtls

import (
	"encoding/hex"
	"net"
	"testing"
)

type dumpConn struct {
	net.Conn
	t *testing.T
}

func (c *dumpConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err == nil {
		c.t.Logf("Read: %s", hex.Dump(b[:n]))
	}
	return
}

func (c *dumpConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if err == nil {
		c.t.Logf("Write: %s", hex.Dump(b))
	}
	return
}

func _TestClientWithOpenSSL(t *testing.T) {
	conn, err := net.Dial("udp", "127.0.0.1:4444")
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig.Clone()
	config.InsecureSkipVerify = true
	c, err := NewClient(&dumpConn{conn, t}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
}

/*
func generateCerts() error {
	pk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tpl := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: "go-dtls",
		},
		IsCA: true,

		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{"go-dtls"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, pk.PublicKey, pk)
	if err != nil {
		return err
	}
	dir, err := ioutil.TempDir("", "test")
	defer os.RemoveAll(dir)
}
*/

func TestHandshakeDecoder(t *testing.T) {
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
		d := &handshakeDecoder{seq: 1}
		for _, i := range seq {
			b, _ := hex.DecodeString(frag[i])
			d.parse(b)
		}
		h := d.read()
		if h == nil || d.seq != 2 {
			t.Fatal("defragmentation:", seq)
		}
		c, err := parseCertificate(h.raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.cert) == 0 {
			t.Fatal("no certificate")
		}
	}
}

func TestHandshakeEncoder(t *testing.T) {
	for _, mtu := range []int{1024, 512, 256, 128, 64, 32} {
		e := &handshakeEncoder{mtu: mtu}
		e.writeRecord(&record{
			typ: recordHandshake,
			ver: DefaultConfig.MinVersion,
			payload: &handshake{
				typ: handshakeClientHello,
				message: &clientHello{
					ver:          DefaultConfig.MaxVersion,
					random:       make([]byte, 32),
					cipherSuites: DefaultConfig.CipherSuites,
					compMethods:  supportedCompression,
					extensions: &extensions{
						renegotiationSupported: true,
						srtpProtectionProfiles: DefaultConfig.SRTPProtectionProfiles,
						extendedMasterSecret:   true,
						sessionTicket:          true,
						signatureAlgorithms:    supportedSignatureAlgorithms,
						supportedPoints:        supportedPointFormats,
						supportedCurves:        supportedCurves,
					},
				},
			},
		})
		b := e.raw
		d := &handshakeDecoder{}
		for len(b) > 0 {
			r, next, err := parseRecord(b)
			if err != nil {
				t.Fatal(err)
			}
			d.parse(r.raw)
			b = next
		}
		h := d.read()
		if h == nil {
			t.Fatal("no message")
		}
		_, err := parseClientHello(h.raw)
		if err != nil {
			t.Fatal(err)
		}
	}
}
