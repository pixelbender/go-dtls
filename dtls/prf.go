package dtls

import (
	"crypto"
	"errors"
)

func lookupTLSHash(hash uint8) (crypto.Hash, error) {
	switch hash {
	case hashSHA1:
		return crypto.SHA1, nil
	case hashSHA256:
		return crypto.SHA256, nil
	case hashSHA384:
		return crypto.SHA384, nil
	default:
		return 0, errors.New("tls: unsupported hash algorithm")
	}
}
