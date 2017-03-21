package dtls

import (
	"errors"
	"fmt"
)

var (
	errAlertFormat = errors.New("dtls: alert format error")
)

const (
	levelWarning = 1
	levelError   = 2
)

const (
	alertCloseNotify            uint8 = 0
	alertUnexpectedMessage      uint8 = 10
	alertBadRecordMAC           uint8 = 20
	alertDecryptionFailed       uint8 = 21
	alertRecordOverflow         uint8 = 22
	alertDecompressionFailure   uint8 = 30
	alertHandshakeFailure       uint8 = 40
	alertBadCertificate         uint8 = 42
	alertUnsupportedCertificate uint8 = 43
	alertCertificateRevoked     uint8 = 44
	alertCertificateExpired     uint8 = 45
	alertCertificateUnknown     uint8 = 46
	alertIllegalParameter       uint8 = 47
	alertUnknownCA              uint8 = 48
	alertAccessDenied           uint8 = 49
	alertDecodeError            uint8 = 50
	alertDecryptError           uint8 = 51
	alertProtocolVersion        uint8 = 70
	alertInsufficientSecurity   uint8 = 71
	alertInternalError          uint8 = 80
	alertUserCanceled           uint8 = 90
	alertNoRenegotiation        uint8 = 100
	alertUnsupportedExtension   uint8 = 110
)

var alertText = map[uint8]string{
	alertCloseNotify:            "close notify",
	alertUnexpectedMessage:      "unexpected message",
	alertBadRecordMAC:           "bad record MAC",
	alertDecryptionFailed:       "decryption failed",
	alertRecordOverflow:         "record overflow",
	alertDecompressionFailure:   "decompression failure",
	alertHandshakeFailure:       "handshake failure",
	alertBadCertificate:         "bad certificate",
	alertUnsupportedCertificate: "unsupported certificate",
	alertCertificateRevoked:     "revoked certificate",
	alertCertificateExpired:     "expired certificate",
	alertCertificateUnknown:     "unknown certificate",
	alertIllegalParameter:       "illegal parameter",
	alertUnknownCA:              "unknown certificate authority",
	alertAccessDenied:           "access denied",
	alertDecodeError:            "error decoding message",
	alertDecryptError:           "error decrypting message",
	alertProtocolVersion:        "protocol version not supported",
	alertInsufficientSecurity:   "insufficient security level",
	alertInternalError:          "internal error",
	alertUserCanceled:           "user canceled",
	alertNoRenegotiation:        "no renegotiation",
	alertUnsupportedExtension:   "unsupported extension",
}

type alert struct {
	level, typ uint8
}

func parseAlert(b []byte) (*alert, error) {
	if len(b) < 2 {
		return nil, errHandshakeFormat
	}
	_ = b[1]
	return &alert{b[0], b[1]}, nil
}

func (a *alert) Error() string {
	v, ok := alertText[a.typ]
	if !ok {
		v = fmt.Sprintf("alert 0x%x", a.typ)
	}
	return fmt.Sprintf("dtls: ", v)
}
