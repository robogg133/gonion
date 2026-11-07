package common

import "testing"

func FuzzParseMicrodescriptor(f *testing.F) {
	f.Add([]byte("onion-key\n-----BEGIN RSA PUBLIC KEY-----\n"), "AAAA")
	f.Add([]byte{}, "")
	f.Fuzz(func(t *testing.T, raw []byte, digest string) {
		_, _ = ParseMicrodescriptor(raw, digest)
	})
}
