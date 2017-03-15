package dtls

type keyAgreement interface {
}

/*
type ecdheKeyAgreement struct {
	version    uint16
	sigType    uint8
	privateKey []byte
	curveid    CurveID

	// publicKey is used to store the peer's public value when X25519 is
	// being used.
	publicKey []byte
	// x and y are used to store the peer's public value when one of the
	// NIST curves is being used.
	x, y *big.Int
}

func (ka *ecdheKeyAgreement) newServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) ([]byte, error) {
	preferredCurves := config.curvePreferences()

NextCandidate:
	for _, candidate := range preferredCurves {
		for _, c := range clientHello.supportedCurves {
			if candidate == c {
				ka.curveid = c
				break NextCandidate
			}
		}
	}

	if ka.curveid == 0 {
		return nil, errors.New("tls: no supported elliptic curves offered")
	}

	var ecdhePublic []byte

	if ka.curveid == X25519 {
		var scalar, public [32]byte
		if _, err := io.ReadFull(config.rand(), scalar[:]); err != nil {
			return nil, err
		}

		curve25519.ScalarBaseMult(&public, &scalar)
		ka.privateKey = scalar[:]
		ecdhePublic = public[:]
	} else {
		curve, ok := curveForCurveID(ka.curveid)
		if !ok {
			return nil, errors.New("tls: preferredCurves includes unsupported curve")
		}

		var x, y *big.Int
		var err error
		ka.privateKey, x, y, err = elliptic.GenerateKey(curve, config.rand())
		if err != nil {
			return nil, err
		}
		ecdhePublic = elliptic.Marshal(curve, x, y)
	}

	// http://tools.ietf.org/html/rfc4492#section-5.4
	serverECDHParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHParams[0] = 3 // named curve
	serverECDHParams[1] = byte(ka.curveid >> 8)
	serverECDHParams[2] = byte(ka.curveid)
	serverECDHParams[3] = byte(len(ecdhePublic))
	copy(serverECDHParams[4:], ecdhePublic)

	sigAndHash := signatureAndHash{signature: ka.sigType}

	if ka.version >= VersionTLS12 {
		var err error
		if sigAndHash.hash, err = pickTLS12HashForSignature(ka.sigType, clientHello.signatureAndHashes); err != nil {
			return nil, err
		}
	}

	digest, hashFunc, err := hashForServerKeyExchange(sigAndHash, ka.version, clientHello.random, hello.random, serverECDHParams)
	if err != nil {
		return nil, err
	}

	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Signer")
	}
	var sig []byte
	switch ka.sigType {
	case signatureECDSA:
		_, ok := priv.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("tls: ECDHE ECDSA requires an ECDSA server key")
		}
	case signatureRSA:
		_, ok := priv.Public().(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("tls: ECDHE RSA requires a RSA server key")
		}
	default:
		return nil, errors.New("tls: unknown ECDHE signature algorithm")
	}
	sig, err = priv.Sign(config.rand(), digest, hashFunc)
	if err != nil {
		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	}

	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(serverECDHParams)+sigAndHashLen+2+len(sig))
	copy(skx.key, serverECDHParams)
	k := skx.key[len(serverECDHParams):]
	if ka.version >= VersionTLS12 {
		k[0] = sigAndHash.hash
		k[1] = sigAndHash.signature
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}*/
