package tls

import (
	"testing"
	"fmt"
	"os"
	"path/filepath"
	"encoding/json"
	"io"
	"encoding/hex"
	"flag"
	"regexp"
	"strings"
	"os/exec"
	"bufio"
	"bytes"
	"errors"
)

var (
	gnutls = flag.String("gnutls", "", "gnutls-cli path")
)

// TestKeysFromPreMaster updates testdata/mastersecrets.txt if gnutls flag is specified
func TestKeysFromPreMaster(t *testing.T) {
	file := filepath.Join("testdata", "mastersecrets.txt")

	if *gnutls != "" {
		w, err := os.Create(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := gnutlsGenerateMasterSecretTests(w); err != nil {
			t.Fatal(err)
		}
	}

	r, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(r)
	check := func(name, field string, got []byte, want string) {
		if h := hex.EncodeToString(got); h != want {
			t.Errorf("%s bad %s\n got: %s\nwant: %s", name, field, h, want)
		}
	}
	for {
		it := struct {
			Name            string
			Version         uint16
			CipherSuite     uint16
			PreMasterSecret string
			ClientRandom    string
			ServerRandom    string
			MasterSecret    string
			ClientKey       string
			ServerKey       string
			ClientIV        string
			ServerIV        string
		}{}
		if err := dec.Decode(&it); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}

		preMasterSecret, _ := hex.DecodeString(it.PreMasterSecret)
		clientRandom, _ := hex.DecodeString(it.ClientRandom)
		serverRandom, _ := hex.DecodeString(it.ServerRandom)
		cipherSuite := getCipherSuite(it.CipherSuite)

		masterSecret := cipherSuite.masterSecret(it.Version, preMasterSecret, clientRandom, serverRandom)
		key := cipherSuite.keyMaterial(it.Version, masterSecret, clientRandom, serverRandom)

		check(it.Name, "master secret", masterSecret, it.MasterSecret)
		check(it.Name, "client key", key.ckey, it.ClientKey)
		check(it.Name, "server key", key.skey, it.ServerKey)

		if it.ClientIV != "" {
			check(it.Name, "client iv", key.civ, it.ClientIV)
		}
		if it.ServerIV != "" {
			check(it.Name, "server iv", key.siv, it.ServerIV)
		}
	}
}

func getCipherSuite(id uint16) *cipherSuite {
	for _, it := range cipherSuites {
		if it.id == id {
			return it
		}
	}
	panic(fmt.Errorf("unsupported cipher suite %x", id))
}

func gnutlsGenerateMasterSecretTests(w io.Writer) error {
	versionMap := map[string]uint16{
		"TLS1.0": VersionTLS10,
		"TLS1.1": VersionTLS11,
		"TLS1.2": VersionTLS12,
	}
	cipherSuiteMap := map[string]uint16{
		"RSA_AES_128_CBC_SHA1": TLS_RSA_WITH_AES_128_CBC_SHA,
	}
	fieldsMap := map[string]string{
		"Version":          "version",
		"Cipher Suite":     "cipherSuite",
		"CLIENT RANDOM":    "clientRandom",
		"SERVER RANDOM":    "serverRandom",
		"PREMASTER SECRET": "preMasterSecret",
		"MASTER SECRET":    "masterSecret",
		"CLIENT WRITE KEY": "clientKey",
		"SERVER WRITE KEY": "serverKey",
		"CLIENT WRITE IV":  "clientIV",
		"SERVER WRITE IV":  "serverIV",
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	for name, p := range map[string]string{
		"TLSv1.0 RSA_WITH_AES_128_CBC_SHA": "NONE:+VERS-TLS1.0:+COMP-NULL:+RSA:+AES-128-CBC:+SHA1",
		"TLSv1.1 RSA_WITH_AES_128_CBC_SHA": "NONE:+VERS-TLS1.1:+COMP-NULL:+RSA:+AES-128-CBC:+SHA1",
		"TLSv1.2 RSA_WITH_AES_128_CBC_SHA": "NONE:+VERS-TLS1.2:+COMP-NULL:+RSA:+AES-128-CBC:+SHA1",
	} {
		args := "--disable-extensions --priority " + p + " --debug 9 google.com"
		b, err := exec.Command(*gnutls, strings.Split(args, " ")...).CombinedOutput()
		s := bufio.NewScanner(bytes.NewReader(b))
		if err != nil {
			for s.Scan() {
				ln := s.Text()
				if strings.Contains(strings.ToLower(ln), "error") {
					err = errors.New(ln)
					break
				}
			}
			return fmt.Errorf("%s: %v", name, err)
		}
		exp := regexp.MustCompile(`[:-] ([\w ]+).*: ([\w\d.]+)$`)
		r := map[string]interface{}{
			"name":    name,
			"command": "gnutls-cli " + args,
		}
		for s.Scan() {
			ln := s.Text()
			m := exp.FindStringSubmatch(ln)
			if len(m) == 0 {
				continue
			}
			k, ok := fieldsMap[strings.TrimSpace(m[1])]
			if ok {
				switch k {
				case "version":
					r[k] = versionMap[m[2]]
				case "cipherSuite":
					r[k] = cipherSuiteMap[m[2]]
				default:
					r[k] = m[2]
				}
			}
		}
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
