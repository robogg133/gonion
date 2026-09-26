package common

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Fixed C Tor certificates and test-only signing keys from test_data.c at
// 3937194. Their identity certifications and crosscerts are independent vectors.
func authorityFixture(t *testing.T, name string) ([]byte, *rsa.PrivateKey, authorityCertificate) {
	t.Helper()
	raw, err := os.ReadFile("testdata/authority-cert-" + name + ".pem")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile("testdata/authority-signkey-" + name + ".pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := parseAuthorityCertificates(raw, time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(certs) != 1 {
		t.Fatalf("Tor certificate: %v", err)
	}
	return raw, key, certs[0]
}

func TestTorAuthorityCertificates(t *testing.T) {
	raw, _, _ := authorityFixture(t, "b")
	now := time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte("2014-11-14"), []byte("2034-11-14"), 1),
		bytes.Replace(raw, []byte("OC+g"), []byte("PC+g"), 1),
		bytes.Replace(raw, []byte("fingerprint AD"), []byte("fingerprint BD"), 1),
		raw[:len(raw)-40],
	} {
		if _, err := parseAuthorityCertificates(bad, now); err == nil {
			t.Fatal("invalid certificate accepted")
		}
	}
	for _, when := range []time.Time{now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0)} {
		if _, err := parseAuthorityCertificates(raw, when); err == nil {
			t.Fatal("certificate accepted outside validity period")
		}
	}
}

func TestConsensusAuthorityQuorum(t *testing.T) {
	a, ak, ac := authorityFixture(t, "b")
	b, bk, bc := authorityFixture(t, "c")
	certs := append(bytes.Clone(a), b...)
	pins := [][20]byte{ac.identity, bc.identity, {1}}
	now := time.Date(2014, 1, 1, 1, 0, 0, 0, time.UTC)
	for _, flavor := range []string{ConsensusFlavorNS, ConsensusFlavorMicrodesc} {
		t.Run(flavor, func(t *testing.T) {
			header := "network-status-version 3"
			if flavor == ConsensusFlavorMicrodesc {
				header += " microdesc"
			}
			body := header + "\nvote-status consensus\nvalid-after 2014-01-01 00:00:00\nfresh-until 2014-01-01 02:00:00\nvalid-until 2014-01-01 03:00:00\ndirectory-footer\n"
			var document bytes.Buffer
			document.WriteString(body)
			sign := func(key *rsa.PrivateKey, cert authorityCertificate) string {
				var digest []byte
				algorithm := ""
				if flavor == ConsensusFlavorMicrodesc {
					h := sha256.Sum256([]byte(body + "directory-signature "))
					digest, algorithm = h[:], "sha256 "
				} else {
					h := sha1.Sum([]byte(body + "directory-signature "))
					digest = h[:]
				}
				sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0, digest)
				if err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("directory-signature %s%X %X\n%s", algorithm, cert.identity, cert.signingDigest, pem.EncodeToMemory(&pem.Block{Type: "SIGNATURE", Bytes: sig}))
			}
			first := sign(ak, ac)
			document.WriteString(first)
			for _, raw := range [][]byte{document.Bytes(), []byte(document.String() + first)} {
				if _, err := AuthenticateConsensus(raw, certs, pins, now); err == nil {
					t.Fatal("one authority, including duplicate signatures, satisfied majority")
				}
			}
			document.WriteString(sign(bk, bc))
			c, err := AuthenticateConsensus(document.Bytes(), certs, pins, now)
			if err != nil || !c.IsAuthenticated() {
				t.Fatalf("valid consensus: %v", err)
			}
			mutated := strings.Replace(document.String(), "02:00:00", "02:10:00", 1)
			if _, err := AuthenticateConsensus([]byte(mutated), certs, pins, now); err == nil {
				t.Fatal("modified signed bytes accepted")
			}
			if _, err := AuthenticateConsensus(document.Bytes(), certs, DefaultAuthorities(), now); err == nil {
				t.Fatal("test identities accepted as public authorities")
			}
			if _, err := AuthenticateConsensus(document.Bytes(), certs, append(pins, ac.identity), now); err == nil {
				t.Fatal("duplicate authority pins accepted")
			}
		})
	}
}
