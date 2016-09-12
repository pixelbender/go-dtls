package dtls

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"
)

func TestDecoder(t *testing.T) {
	t.Parallel()
	data, _ := hex.DecodeString("16feff000000000000000000980100008c000000000000008cfefded6b5094c6c428fc41606dc37b295f51392b1033fc9549775e457ffbeac3ea6e00000022c02bc02f009ecca9cca8cc14cc13c009c0130033c00ac0140039009c002f0035000a01000040ff010001000017000000230000000d0012001006010603050105030401040302010203000e000700040002000100000b00020100000a00080006001d00170018")
	dec := &handshakeDecoder{
		receiver: &receiver{
			inner: bytes.NewReader(data),
		},
	}
	msg, err := dec.ReadMessage()
	if err != nil {
		t.Fatal("read", err)
	}
	hello := msg.(*clientHello)
	if hello == nil {
		t.Fatal("message type error")
	}
	if hello.Version != VersionDTLS12 {
		t.Fatal("handshake version")
	}
	random, _ := hex.DecodeString("ed6b5094c6c428fc41606dc37b295f51392b1033fc9549775e457ffbeac3ea6e")
	if !bytes.Equal(hello.RandomBytes, random) {
		t.Fatal("random")
	}
	if hello.Session != nil {
		t.Fatal("session")
	}
	if hello.Cookie != nil {
		t.Fatal("cookie")
	}
	log.Printf("%#v", msg)
}
