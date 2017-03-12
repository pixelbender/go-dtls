package dtls

import "crypto/elliptic"

const (
	extRenegotiationInfo    uint16 = 0xff01
	extExtendedMasterSecret uint16 = 0x0017
	extSessionTicket        uint16 = 0x0023
	extSignatureAlgorithms  uint16 = 0x000d
	extUseSRTP              uint16 = 0x000e
	extSupportedPoints      uint16 = 0x000b
	extSupportedCurves      uint16 = 0x000a
)

const (
	SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001
	SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002
	SRTP_NULL_HMAC_SHA1_80      = 0x0005
	SRTP_NULL_HMAC_SHA1_32      = 0x0006
)

const (
	signRSA    uint8 = 1
	signECDSA  uint8 = 3
	signRSAPSS uint8 = 8
)

const (
	hashSHA1   uint8 = 2
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
	hashSHA512 uint8 = 6
)

type signatureAlgorithm struct {
	hash, sign uint8
}

const (
	pointUncompressed uint8 = 0
)

const (
	secp256r1  uint16 = 23
	secp384r1  uint16 = 24
	secp521r1  uint16 = 25
	ecdhx25519 uint16 = 29
)

func getEllipticCurve(v uint16) elliptic.Curve {
	switch v {
	case secp256r1:
		return elliptic.P256()
	case secp384r1:
		return elliptic.P384()
	case secp521r1:
		return elliptic.P521()
	default:
		return nil
	}
}

type extensions struct {
	renegotiationSupported  bool
	renegotiationInfo       []byte
	srtpProtectionProfiles  []uint16
	srtpMasterKeyIdentifier []byte
	extendedMasterSecret    bool
	sessionTicket           bool
	signatureAlgorithms     []signatureAlgorithm
	supportedPoints         []uint8
	supportedCurves         []uint16
}

func parseExtensions(b []byte) (*extensions, error) {
	var v, r []byte
	e := &extensions{}

	for len(b) > 3 {
		_ = b[3]
		typ := uint16(b[0])<<8 | uint16(b[1])
		if v, b = split2(b[2:]); v == nil {
			return nil, errHandshakeFormat
		}
		switch typ {
		case extRenegotiationInfo:
			e.renegotiationSupported = true
			if e.renegotiationInfo, r = split(v); r == nil {
				return nil, errHandshakeFormat
			}
		case extExtendedMasterSecret:
			e.extendedMasterSecret = true
		case extSessionTicket:
			e.sessionTicket = true
		case extSignatureAlgorithms:
			if v, _ = split2(v); v == nil {
				return nil, errHandshakeFormat
			}
			e.signatureAlgorithms = make([]signatureAlgorithm, len(v)>>1)
			for i := range e.signatureAlgorithms {
				_ = v[1]
				e.signatureAlgorithms[i], v = signatureAlgorithm{v[0], v[1]}, v[2:]
			}
		case extUseSRTP:
			if v, r = split2(v); v == nil {
				return nil, errHandshakeFormat
			}
			e.srtpProtectionProfiles = make([]uint16, len(v)>>1)
			for i := range e.srtpProtectionProfiles {
				_ = v[1]
				e.srtpProtectionProfiles[i], v = uint16(v[0])|uint16(v[1]), v[2:]
			}
			if e.srtpMasterKeyIdentifier, r = split(r); r == nil {
				return nil, errHandshakeFormat
			}
		case extSupportedPoints:
			if e.supportedPoints, r = split(v); r == nil {
				return nil, errHandshakeFormat
			}
		case extSupportedCurves:
			if v, _ = split2(v); v == nil {
				return nil, errHandshakeFormat
			}
			e.supportedCurves = make([]uint16, len(v)>>1)
			for i := range e.supportedCurves {
				_ = v[1]
				e.supportedCurves[i], v = uint16(v[0])|uint16(v[1]), v[2:]
			}
		}
	}
	return e, nil
}

func (e *extensions) marshal(b []byte) []byte {
	var v []byte
	if e.renegotiationSupported {
		n := len(e.renegotiationInfo)
		s := n + 1
		v, b = grow(b, 4+s)
		_ = v[4]
		v[0], v[1], v[2], v[3], v[4] = uint8(extRenegotiationInfo>>8), uint8(extRenegotiationInfo&0xff), uint8(s>>8), uint8(s), uint8(n)
		copy(v[5:], e.renegotiationInfo)
	}
	if e.extendedMasterSecret {
		v, b = grow(b, 4)
		_ = v[3]
		v[0], v[1], v[2], v[3] = 0, uint8(extExtendedMasterSecret), 0, 0
	}
	if e.sessionTicket {
		v, b = grow(b, 4)
		_ = v[3]
		v[0], v[1], v[2], v[3] = 0, uint8(extSessionTicket), 0, 0
	}
	if n := len(e.signatureAlgorithms) << 1; n > 0 {
		s := n + 2
		v, b = grow(b, 4+s)
		_ = v[5]
		v[0], v[1], v[2], v[3], v[4], v[5], v = 0, uint8(extSignatureAlgorithms), uint8(s>>8), uint8(s), uint8(n>>8), uint8(n), v[6:]
		for _, a := range e.signatureAlgorithms {
			_ = v[1]
			v[0], v[1], v = a.hash, a.sign, v[2:]
		}
	}
	if n := len(e.srtpProtectionProfiles) << 1; n > 0 {
		s := n + 3 + len(e.srtpMasterKeyIdentifier)
		v, b = grow(b, 4+s)
		_ = v[5]
		v[0], v[1], v[2], v[3], v[4], v[5], v = 0, uint8(extUseSRTP), uint8(s>>8), uint8(s), uint8(n>>8), uint8(n), v[6:]
		for _, p := range e.srtpProtectionProfiles {
			_ = v[1]
			v[0], v[1], v = uint8(p>>8), uint8(p), v[2:]
		}
		v[0] = uint8(copy(v[1:], e.srtpMasterKeyIdentifier))
	}
	if n := len(e.supportedPoints); n > 0 {
		s := n + 1
		v, b = grow(b, 4+s)
		_ = v[4]
		v[0], v[1], v[2], v[3], v[4] = 0, uint8(extSupportedPoints), uint8(s>>8), uint8(s), uint8(n)
		copy(v[5:], e.supportedPoints)
	}
	if n := len(e.supportedCurves) << 1; n > 0 {
		s := n + 2
		v, b = grow(b, 4+s)
		_ = v[5]
		v[0], v[1], v[2], v[3], v[4], v[5] = 0, uint8(extSupportedCurves), uint8(s>>8), uint8(s), uint8(n>>8), uint8(n)
		v = v[6:]
		for _, c := range e.supportedCurves {
			_ = v[1]
			v[0], v[1], v = uint8(c>>8), uint8(c), v[2:]
		}
	}
	return b
}
