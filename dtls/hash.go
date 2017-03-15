package dtls

/*
type extHash struct {
	hash.Hash
	md hash.Hash
}

func (h extHash) Write(b []byte) (n int, error) {
	h.md.Write(b)
	return h.Hash.Write(b)
}

func (h extHash) Sum(b []byte) []byte {
	out := make([]byte, 0, h.Hash.Size() + md5.Size)
	out = h.clientMD5.Sum(out)
	return h.client.Sum(out)
}

type finish struct {
	client    hash.Hash
	server    hash.Hash
}

func newHash(ver uint16, suite *cipherSuite) *finish {
	switch ver {
	case VersionDTLS10:
		return &hash{sha1.New(), sha1.New(), md5.New(), md5.New(), prf10}
		prf10, crypto.Hash(0)
	case VersionDTLS12:
		if suite.flags&suiteSHA384 != 0 {
			return &hash{sha512.New384(), sha512.New384(), buffer, version, prf12(crypto.SHA384)}
		}
		return &hash{sha256.New(), sha256.New(), buffer, version, prf12(crypto.SHA256)}

	}
	var buffer []byte
	if version == VersionSSL30 || version >= VersionTLS12 {
		buffer = []byte{}
	}

	prf, hash := prfAndHashForVersion(version, cipherSuite)
	if hash != 0 {
		return finishedHash{hash.New(), hash.New(), nil, nil, buffer, version, prf}
	}

	return finishedHash{sha1.New(), sha1.New(), md5.New(), md5.New(), buffer, version, prf}
}

func (f *finish) s(result, secret, label, seed []byte) {

}

type prf func(result, secret, label, seed []byte)

func prf12(hashFunc func() hash.Hash) prf {
	return func(result, secret, label, seed []byte) {
		phash(result, secret, label, seed, hashFunc)
	}
}

func prf10(result, secret, label, seed []byte) {
	s1, s2 := secret[0: (len(secret)+1)/2], secret[len(secret)/2:]
	phash(result, s1, label, seed, md5.New)
	result2 := make([]byte, len(result))
	phash(result2, s2, label, seed, sha1.New)
	for i, b := range result2 {
		result[i] ^= b
	}
}

func phash(result, secret, label, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(label)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(label)
		h.Write(seed)
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
*/
