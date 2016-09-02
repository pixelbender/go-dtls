# Golang implementation of DTLS Protocol

[![Build Status](https://travis-ci.org/pixelbender/go-dtls.svg)](https://travis-ci.org/pixelbender/go-dtls)
[![Coverage Status](https://coveralls.io/repos/github/pixelbender/go-dtls/badge.svg?branch=master)](https://coveralls.io/github/pixelbender/go-dtls?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/pixelbender/go-dtls)](https://goreportcard.com/report/github.com/pixelbender/go-dtls)
[![GoDoc](https://godoc.org/github.com/pixelbender/go-dtls?status.svg)](https://godoc.org/github.com/pixelbender/go-dtls)

Work in progress...

## Features

- [ ] Client handshake
- [ ] Server handshake
- [ ] Retransmission
- [ ] PMTU Discovery
- [ ] ...

## Installation

```sh
go get github.com/pixelbender/go-dtls
```

## DTLS Client

```go
package main

import (
    "github.com/pixelbender/go-dtls/dtls"
    "crypto/tls"
    "log"
)

func main() {
    conn, err := dtls.Dial("udp", "example.com:5000", &tls.Config{})
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    // Use conn as net.Conn...
}
```

## DTLS Server

```go
package main

import (
    "github.com/pixelbender/go-dtls/dtls"
    "crypto/tls"
    "log"
)

func main() {
    cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
    if err != nil {
        log.Fatal(err)
    }
    config := &tls.Config{Certificates: []tls.Certificate{cert}}
    
    l, err := dtls.Listen("udp", ":5000", config)
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()
    for {
        // Use l as net.Listener since DTLS is connection-oriented protocol
        conn, err := l.Accept()
        if err != nil {
            log.Fatal(err)
        }
        go func() {
            defer conn.Close()
            // Serve conn as net.Conn...
        }()
    }
}
```

## Specifications

- [RFC 4347: DTLS Version 1.0](https://tools.ietf.org/html/rfc4347)
- [RFC 6347: DTLS Version 1.2](https://tools.ietf.org/html/rfc6347)
