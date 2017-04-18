package tls

import (
	"testing"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"flag"
	"io/ioutil"
	"os/exec"
	"io"
	"bufio"
	"time"
	"syscall"
	"sync"
	"errors"
	"math/rand"
)

var (
	openssl = flag.String("openssl", "", "openssl path")
)

func TestOpenSSL(t *testing.T) {
	if *openssl == "" {
		t.Skip("openssl is not specified")
	}
	dir, err := ioutil.TempDir("", "go-tls")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	t.Log(run(dir, *openssl, "version"))
	run(dir, *openssl, "req -x509 -newkey rsa:4096 -keyout rsa_key.pem -out rsa_cert.pem -days 365 -nodes -subj /CN=localhost")

	testHandshake := func(addr string) error {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return err
		}
		config := defaultConfig.Clone()
		config.Rand = rand.New(rand.NewSource(0))
		cli, err := newClient(&logConn{Conn: conn, Logf: t.Logf}, config)
		if err != nil {
			conn.Close()
			return err
		}
		t.Log("connected")
		cli.Close()
		return nil
	}

	testServer := func(args, addr string) error {
		srv, err := newProcess(dir, *openssl, args)
		if err != nil {
			return err
		}
		defer srv.Close()
		var (
			once sync.Once
			result = make(chan error)
		)
		for {
			select {
			case err := <-result:
				return err
			case msg := <-srv.out:
				if strings.HasPrefix(msg, "Error") {
					return errors.New(msg)
				} else if strings.HasPrefix(msg, "ACCEPT") {
					go once.Do(func() {
						result <- testHandshake(addr)
					})
				} else {
					t.Logf("openssl: %s", msg)
				}
			case <-time.After(5 * time.Second):
				return errors.New("timeout")
			}
		}
		return nil
	}

	for name, it := range map[string]string{
		"TLS1.2 RSA_WITH_AES_128_CBC_SHA": "-cipher AES128-SHA -tls1_2",
	} {
		args := "s_server -cert rsa_cert.pem -key rsa_key.pem -accept 32000 " + it
		addr := "127.0.0.1:32000"
		if err := testServer(args, addr); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func run(dir, name, args string) string {
	cmd := exec.Command(name, strings.Fields(args)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(out))
}

type process struct {
	*exec.Cmd
	io.Writer
	out chan string
}

func newProcess(dir, name, args string) (*process, error) {
	cmd := exec.Command(name, strings.Fields(args)...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &process{
		cmd,
		stdin,
		make(chan string, 10),
	}
	for _, r := range []io.Reader{stdout, stderr} {
		go func(r io.Reader) {
			s := bufio.NewScanner(r)
			for s.Scan() {
				p.out <- s.Text()
			}
		}(r)
	}
	return p, nil
}

func (p *process) Close() {
	syscall.Kill(-p.Process.Pid, syscall.SIGKILL)
	p.Wait()
}

type logConn struct {
	net.Conn
	Logf func(format string, args ...interface{})
	buf  []byte
}

func (c *logConn) Read(b []byte) (n int, err error) {
	for {
		if len(c.buf) > 0 {
			n = copy(b, c.buf)
			c.buf = c.buf[n:]
			return
		}
		c.buf = make([]byte, 102400)
		n, err = c.Conn.Read(c.buf)
		if err != nil {
			n = 0
			return
		}
		c.buf = c.buf[:n]
		if c.Logf != nil {
			c.Logf("<\n%s", hex.Dump(c.buf))
		}
	}
	return
}

func (c *logConn) Write(b []byte) (n int, err error) {
	if n, err = c.Conn.Write(b); err == nil {
		c.Logf(">\n%s", hex.Dump(b))
	}
	return
}
