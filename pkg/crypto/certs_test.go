package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	_ "embed"
)

//go:embed testdata/cert2.der
var cert2Bytes []byte

//go:embed testdata/cert4.bin
var cert4Bytes []byte

//go:embed testdata/cert5.bin
var cert5Bytes []byte

//go:embed testdata/cert7.bin
var cert7Bytes []byte

//go:embed testdata/tls.bin
var tlsBytes []byte

func TestRelayCertificateChainPositive(t *testing.T) {
	certs := map[uint8][]byte{
		2: bytes.Clone(cert2Bytes),
		4: bytes.Clone(cert4Bytes),
		5: bytes.Clone(cert5Bytes),
		7: bytes.Clone(cert7Bytes),
	}
	rsaID, edID, err := VerifyRelayCertificates(certs, tlsBytes)
	if err != nil {
		t.Fatalf("positive chain rejected: %v", err)
	}
	wantRSA, _ := hex.DecodeString("d2db1e509e40b611b6fc6491b4927260aea24164")
	wantEd, _ := hex.DecodeString("57bdc3e1725f866badc49225b6ca5820f3d6cdf2fffb1dbde9a0aa607b85fc72")
	if rsaID != [20]byte(wantRSA) {
		t.Fatalf("rsa identity mismatch: got %x", rsaID)
	}
	if edID != [32]byte(wantEd) {
		t.Fatalf("ed identity mismatch: got %x", edID)
	}
}

func TestRelayCertificateChainNegatives(t *testing.T) {
	cloneMap := func() map[uint8][]byte {
		return map[uint8][]byte{
			2: bytes.Clone(cert2Bytes),
			4: bytes.Clone(cert4Bytes),
			5: bytes.Clone(cert5Bytes),
			7: bytes.Clone(cert7Bytes),
		}
	}
	check := func(t *testing.T, certs map[uint8][]byte, tls []byte) {
		t.Helper()
		_, _, err := VerifyRelayCertificates(certs, tls)
		if err == nil || err.Error() == "" {
			t.Fatalf("expected non-empty rejection error, got %v", err)
		}
	}

	t.Run("missing type 4", func(t *testing.T) {
		c := cloneMap()
		delete(c, 4)
		check(t, c, tlsBytes)
	})
	t.Run("missing type 5", func(t *testing.T) {
		c := cloneMap()
		delete(c, 5)
		check(t, c, tlsBytes)
	})
	t.Run("missing type 2", func(t *testing.T) {
		c := cloneMap()
		delete(c, 2)
		check(t, c, tlsBytes)
	})
	t.Run("missing type 7", func(t *testing.T) {
		c := cloneMap()
		delete(c, 7)
		check(t, c, tlsBytes)
	})
	t.Run("truncated cert4", func(t *testing.T) {
		c := cloneMap()
		c[4] = c[4][:len(c[4])-1]
		check(t, c, tlsBytes)
	})
	t.Run("truncated cert5", func(t *testing.T) {
		c := cloneMap()
		c[5] = c[5][:len(c[5])-10]
		check(t, c, tlsBytes)
	})
	t.Run("truncated cert2", func(t *testing.T) {
		c := cloneMap()
		c[2] = c[2][:len(c[2])-5]
		check(t, c, tlsBytes)
	})
	t.Run("truncated cert7", func(t *testing.T) {
		c := cloneMap()
		c[7] = c[7][:len(c[7])-1]
		check(t, c, tlsBytes)
	})
	t.Run("flipped cert4 byte", func(t *testing.T) {
		c := cloneMap()
		c[4][0] ^= 0x01
		check(t, c, tlsBytes)
	})
	t.Run("flipped cert5 byte", func(t *testing.T) {
		c := cloneMap()
		c[5][10] ^= 0x01
		check(t, c, tlsBytes)
	})
	t.Run("flipped cert7 byte", func(t *testing.T) {
		c := cloneMap()
		c[7][40] ^= 0x01
		check(t, c, tlsBytes)
	})
	t.Run("types swapped 4 and 5", func(t *testing.T) {
		c := cloneMap()
		c[4], c[5] = c[5], c[4]
		check(t, c, tlsBytes)
	})
	t.Run("tls digest mismatch", func(t *testing.T) {
		c := cloneMap()
		tls := bytes.Clone(tlsBytes)
		tls[0] ^= 0x01
		check(t, c, tls)
	})
	t.Run("cross-cert edID mismatch", func(t *testing.T) {
		c := cloneMap()
		c[7][0] ^= 0x01
		check(t, c, tlsBytes)
	})
	t.Run("all zero cert4", func(t *testing.T) {
		c := cloneMap()
		c[4] = make([]byte, len(cert4Bytes))
		check(t, c, tlsBytes)
	})
	t.Run("all zero cert2", func(t *testing.T) {
		c := cloneMap()
		c[2] = make([]byte, len(cert2Bytes))
		check(t, c, tlsBytes)
	})
	t.Run("empty map", func(t *testing.T) {
		check(t, map[uint8][]byte{}, tlsBytes)
	})
}

func TestParseIdentityVSigningCertBasics(t *testing.T) {
	cert, err := ParseIdentityVSigningCert(cert4Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != 4 {
		t.Fatalf("wrong type: %d", cert.CertType)
	}
	if len(cert.CertifiedKey) != 32 {
		t.Fatalf("bad certified key length: %d", len(cert.CertifiedKey))
	}
	// Truncated input must fail.
	if _, err := ParseIdentityVSigningCert(cert4Bytes[:len(cert4Bytes)-1]); err == nil || err.Error() == "" {
		t.Fatal("truncated cert accepted")
	}
	// Version flip must fail.
	bad := bytes.Clone(cert4Bytes)
	bad[0] = 2
	if _, err := ParseIdentityVSigningCert(bad); err == nil || err.Error() == "" {
		t.Fatal("bad version accepted")
	}
}

func TestTorCertVerify(t *testing.T) {
	cert, err := ParseIdentityVSigningCert(cert4Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Clone(cert.Extensions[4].Data)
	if err := cert.Verify(key, time.Now()); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	key[0] ^= 1
	if err := cert.Verify(key, time.Now()); err == nil || err.Error() == "" {
		t.Fatal("wrong signer accepted")
	}
	if err := cert.Verify(make([]byte, 32), time.Now()); err == nil || err.Error() == "" {
		t.Fatal("all-zero signer accepted")
	}
}
