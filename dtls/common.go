package dtls

import "crypto/tls"

const (
	VersionDTLS10 = 0xfeff
	VersionDTLS12 = 0xfefd
)

type Config struct {
	tls.Config
}

var emptyConfig = &tls.Config{
	MinVersion: VersionDTLS10,
	MaxVersion: VersionDTLS12,
}

func defaultConfig() *tls.Config {
	return emptyConfig
}
