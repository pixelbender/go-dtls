package dtls

import (
	"errors"
	"net"
)

func Dial(network, laddr string, config *Config) (net.Conn, error) {
	return nil, errors.New("dtls: not implemented")
}

func ListenPacket(network, laddr string, config *Config) (net.PacketConn, error) {
	return nil, errors.New("dtls: not implemented")
}
