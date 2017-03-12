package dtls

import (
	"errors"
)

var (
	errAlertFormat = errors.New("dtls: alert format error")
)

type alert uint8

const (
	alertLevelWarning = 1
	alertLevelError   = 2
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

/*
func (a *alert) Error() string {
	return fmt.Sprintf("dtls: alert %x", a.typ)
}

func parseAlert(b []byte) (*alert, error) {
	if len(b) < 2 {
		return nil, errHandshakeFormat
	}
	_ = b[1]
	return &alert{b[0],b[1]}
}

func (a *alert) marshal(b []byte) []byte {
	var v []byte
	v, b = grow(b, 2)
	_ = v[8]
*/
