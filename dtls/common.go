package dtls

import (
	"crypto/tls"
)

// DTLS client or server configuration
type Config struct {
	Certificates []tls.Certificate
}
