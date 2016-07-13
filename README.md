# Golang DTLS Protocol Implementation

[![Join the chat at https://gitter.im/pixelbender/go-dtls](https://badges.gitter.im/pixelbender/go-dtls.svg)](https://gitter.im/pixelbender/go-dtls?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

There is no working release yet. Stay tuned.

## Roadmap

- [ ] [RFC 4347: DTLS Version 1.0](https://tools.ietf.org/html/rfc4347)
- [ ] [RFC 6347: DTLS Version 1.2](https://tools.ietf.org/html/rfc6347)
- [ ] [RFC 5764: DTLS Extension for the SRTP](https://tools.ietf.org/html/rfc5764)

## Usage

```sh
go get github.com/pixelbender/go-dtls
```

```go
cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
if err != nil {
    return err
}
config := dtls.Config{Certificates: []tls.Certificate{cert}}

// Client

conn, err := dtls.Dial("udp", "example.com:5000", &config)

// Server

listener, err := dtls.Listen("udp", ":5000", &config)
```
