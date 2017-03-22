package dtls

import (
	"log"
	"testing"
)

func _TestServer(t *testing.T) {
	l, err := Listen("udp4", "127.0.0.1:4444", nil)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%v", l.Addr())
	for {
		_, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
	}
}
