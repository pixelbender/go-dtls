package dtls

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"hash"
)

var (
	masterSecret   = []byte("master secret")
	clientFinished = []byte("client finished")
	serverFinished = []byte("server finished")
)

type md5sha1 struct {
	hash.Hash
	md hash.Hash
}

func newMD5SHA1() hash.Hash {
	return &md5sha1{sha1.New(), md5.New()}
}

func (h *md5sha1) Write(b []byte) (int, error) {
	h.md.Write(b)
	return h.Write(b)
}

func (h *md5sha1) Reset() {
	h.md.Reset()
	h.Reset()
}

func (h *md5sha1) Sum(b []byte) []byte {
	return h.Sum(h.md.Sum(b))
}

/*
type finishedHash struct {
	hash func() hash.Hash
	ver  uint16
	buf  []byte
}

func newSHA(ver uint16) *finishedHash {
	h := sha256.New
	if ver == VersionDTLS10 {
		h = newMD5SHA1
	}
	return &finishedHash{h, ver, nil}
}

func newSHA384(ver uint16) *finishedHash {
	return &finishedHash{sha512.New384, ver, nil}
}

func (h *finishedHash) Reset() {
	if h.buf != nil {
		h.buf = h.buf[:0]
	}
}

func (h *finishedHash) Write(b []byte) (int, error) {
	h.buf = append(h.buf, b...)
	return len(b), nil
}

func (h *finishedHash) Sum() []byte {
	r := h.hash()
	r.Write(h.buf)
	return r.Sum(nil)
}

func (h *finishedHash) sumServer(secret []byte) []byte {
	return h.prf(secret, clientFinished, h.Sum())
}

func (h *finishedHash) sumClient(secret []byte) []byte {
	return h.prf(secret, serverFinished, h.Sum())
}

func (h *finishedHash) prf(secret, label, seed []byte) []byte {
	if h.ver == VersionDTLS10 {
		s1, s2 := secret[0: (len(secret)+1)/2], secret[len(secret)/2:]
		r := phash(md5.New, s1, label, seed)
		for i, x := range phash(sha1.New, s2, label, seed) {
			r[i] ^= x
		}
		return r
	}
	return phash(h.hash, secret, label, seed)
}
*/

func phash(hash func() hash.Hash, result, secret []byte, params ...[]byte) {
	h := hmac.New(hash, secret)
	for _, p := range params {
		h.Write(p)
	}
	a := h.Sum(nil)
	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		for _, p := range params {
			h.Write(p)
		}
		b := h.Sum(nil)
		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo
		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}
