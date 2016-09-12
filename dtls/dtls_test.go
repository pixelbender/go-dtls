package dtls

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestDTLSv1ClientHandshakeWithOpenSSL(t *testing.T) {
	dir, err := ioutil.TempDir("", "go-dtls")
	if err != nil {
		t.Fatalf("tempdir error: %v", err)
	}
	defer os.RemoveAll(dir)

	/*
		cmd := exec.Command("openssl", strings.Fields("req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes -subj /C=/ST=/L=/O=/OU=/CN=*.example.com")...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("openssl req: %v\n%s", err, out)
		}


		go func() {
			cmd := exec.Command("openssl", strings.Fields("s_server -cert cert.pem -key key.pem -dtls1 -accept 30000")...)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("openssl s_server: %v\n%s", err, out)
			}
			quit <- true
		}()
	*/
	/*conn, err := DialWithDialer(&net.Dialer{Timeout: 5 * time.Second }, "udp", ":30000", &Config{InsecureSkipVerify: false})
	if err != nil {
		t.Fatalf("dial error %v", err)
	}
	t.Logf("conn %v", conn)*/
}
