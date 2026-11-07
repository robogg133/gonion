package crypto

import "testing"

func FuzzParseIdentityVSigningCert(f *testing.F) {
	f.Add(cert4Bytes)
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 104))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseIdentityVSigningCert(b)
	})
}
