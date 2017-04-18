package dtls

import (
	"errors"
	"strconv"
)

var (
	errAlertFormat = errors.New("dtls: alert format error")
)

const (
	levelError = 2
)

const (
	alertCloseNotify            alert = 0
	alertUnexpectedMessage      alert = 10
	alertBadRecordMAC           alert = 20
	alertDecryptionFailed       alert = 21
	alertRecordOverflow         alert = 22
	alertDecompressionFailure   alert = 30
	alertHandshakeFailure       alert = 40
	alertBadCertificate         alert = 42
	alertUnsupportedCertificate alert = 43
	alertCertificateRevoked     alert = 44
	alertCertificateExpired     alert = 45
	alertCertificateUnknown     alert = 46
	alertIllegalParameter       alert = 47
	alertUnknownCA              alert = 48
	alertAccessDenied           alert = 49
	alertDecodeError            alert = 50
	alertDecryptError           alert = 51
	alertProtocolVersion        alert = 70
	alertInsufficientSecurity   alert = 71
	alertInternalError          alert = 80
	alertUserCanceled           alert = 90
	alertNoRenegotiation        alert = 100
	alertUnsupportedExtension   alert = 110
)

var alertText = map[alert]string{
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

type alert uint8

func (a alert) String() string {
	if v, ok := alertText[a]; ok {
		return "dtls: " + v
	}
	return "dtls: alert(" + strconv.Itoa(int(a)) + ")"
}

func (a alert) Error() string {
	return a.String()
}

func parseAlert(b []byte) (uint8, alert, error) {
	if len(b) < 2 {
		return 0, 0, errAlertFormat
	}
	_ = b[1]
	return b[0], alert(b[1]), nil
}
