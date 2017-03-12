package dtls

import (
	"testing"
	"net"
)

func TestClientWithOpenSSL(t *testing.T) {
	conn, err := net.Dial("udp", "127.0.0.1:4444")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewClient(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
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
