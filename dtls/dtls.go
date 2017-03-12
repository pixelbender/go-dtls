package dtls

import "crypto/tls"

const (
	VersionDTLS10 uint16 = 0xfeff
	VersionDTLS12 uint16 = 0xfefd
)

var supportedSignatureAlgorithms = []signatureAlgorithm{
	{hashSHA256, signRSA},
	{hashSHA256, signECDSA},
	{hashSHA384, signRSA},
	{hashSHA384, signECDSA},
	{hashSHA1, signRSA},
	{hashSHA1, signECDSA},
}

var supportedCurves = []uint16{
	secp256r1,
	secp384r1,
	secp521r1,
	ecdhx25519,
}

var supportedCompression = []uint8{
	compNone,
}

var supportedCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var supportedPointFormats = []uint8{
	pointUncompressed,
}

var srtpSupportedProtectionProfiles = []uint16{
	SRTP_AES128_CM_HMAC_SHA1_80,
	SRTP_AES128_CM_HMAC_SHA1_32,
}
