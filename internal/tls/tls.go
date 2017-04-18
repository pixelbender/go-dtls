package tls

const (
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

const (
	VersionDTLS10 uint16 = VersionTLS11
	VersionDTLS12 uint16 = VersionTLS12
	VersionDTLS13 uint16 = VersionTLS13
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

var supportedPointFormats = []uint8{
	pointUncompressed,
}

var supportedCompressionMethods = []uint8{
	compressionNone,
}
