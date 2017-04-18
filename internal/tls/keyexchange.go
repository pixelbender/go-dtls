package tls

import (
	"crypto/x509"
	"crypto/rsa"
	"reflect"
	"io"
)

type keyExchange interface {
	newClientKey(config *Config, clientHello *clientHello, cert *x509.Certificate) ([]byte, handshakeMessage, error)
}

func keyExchangeRSA() keyExchange {
	return &keyRSA{}
}

type keyRSA struct {
}

func (k *keyRSA) newClientKey(config *Config, clientHello *clientHello, cert *x509.Certificate) (preMasterSecret []byte, clientKey handshakeMessage, err error) {
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err = &errUnsupportedType{"certificate public key", reflect.TypeOf(cert.PublicKey)}
		return
	}
	p := make([]byte, 48)
	p[0], p[1] = uint8(clientHello.ver>>8), uint8(clientHello.ver)
	if _, err = io.ReadFull(config.Rand, p[2:]); err != nil {
		return
	}
	enc, err := rsa.EncryptPKCS1v15(config.Rand, key, p)
	if err != nil {
		return
	}
	return p, &clientKeyExchangeRSA{pub: enc}, nil
}

type errUnsupportedType struct {
	name string
	typ  reflect.Type
}

func (e errUnsupportedType) String() string {
	return "tls: unsupported type of " + e.name + ": " + e.typ.String()
}

func (e errUnsupportedType) Error() string {
	return e.String()
}
