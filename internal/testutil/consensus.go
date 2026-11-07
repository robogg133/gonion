// Package testutil provides authenticated, offline directory fixtures for tests.
// It is not imported by the client implementation.
package testutil

import (
	"bytes"

	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

//go:embed tor-test-md.fixture
var microdescriptor []byte

var authorityKeys = sync.OnceValues(func() ([2]*rsa.PrivateKey, error) {
	var keys [2]*rsa.PrivateKey
	for i := range keys {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return keys, err
		}
		keys[i] = key
	}
	return keys, nil
})

// Consensus signs a small test network for the supplied time, then verifies it
// with an explicitly pinned test authority and hash-checked microdescriptors.
// No production authority, authentication marker, or clock check is overridden.
func Consensus(t testing.TB, now time.Time) *common.Consensus {
	return consensus(t, now, nil, nil)
}

// ConsensusWithHSDirs signs the requested directory flags and protocol
// capabilities before authentication, rather than modifying a trusted view.
func ConsensusWithHSDirs(t testing.TB, now time.Time, indices ...int) *common.Consensus {
	t.Helper()
	hsdirs := make(map[int]bool, len(indices))
	for _, index := range indices {
		if index < 0 || index >= 6 {
			t.Fatal("test HSDir index out of range")
		}
		hsdirs[index] = true
	}
	return consensus(t, now, hsdirs, nil)
}

// ConsensusWithFamily signs mutual family declarations in the descriptor
// digests for two relays before verifying and hydrating the directory.
func ConsensusWithFamily(t testing.TB, now time.Time, a, b int) *common.Consensus {
	t.Helper()
	if a < 0 || a >= 6 || b < 0 || b >= 6 || a == b {
		t.Fatal("invalid test family indices")
	}
	return consensus(t, now, nil, map[int]int{a: b, b: a})
}

func consensus(t testing.TB, now time.Time, hsdirs map[int]bool, family map[int]int) *common.Consensus {
	t.Helper()
	keys, err := authorityKeys()
	if err != nil {
		t.Fatal(err)
	}
	identity, signing := keys[0], keys[1]
	idDER := x509.MarshalPKCS1PublicKey(&identity.PublicKey)
	skDER := x509.MarshalPKCS1PublicKey(&signing.PublicKey)
	id, skID := sha1.Sum(idDER), sha1.Sum(skDER)
	pemObject := func(kind string, data []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}))
	}
	sign := func(key *rsa.PrivateKey, digest []byte) []byte {
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0, digest)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	stamp := func(d time.Duration) string { return now.UTC().Add(d).Format(common.CONSENSUS_DATE_FORMAT) }
	cert := fmt.Sprintf("dir-key-certificate-version 3\nfingerprint %X\ndir-key-published %s\ndir-key-expires %s\ndir-identity-key\n%sdir-signing-key\n%sdir-key-crosscert\n%sdir-key-certification\n",
		id, stamp(-24*time.Hour), stamp(24*time.Hour), pemObject("RSA PUBLIC KEY", idDER), pemObject("RSA PUBLIC KEY", skDER), pemObject("ID SIGNATURE", sign(signing, id[:])))
	certDigest := sha1.Sum([]byte(cert))
	cert += pemObject("SIGNATURE", sign(identity, certDigest[:]))

	var body bytes.Buffer
	fmt.Fprintf(&body, "network-status-version 3 microdesc\nvote-status consensus\nvalid-after %s\nfresh-until %s\nvalid-until %s\n", stamp(-time.Hour), stamp(time.Hour), stamp(2*time.Hour))
	mds := make(map[string][]byte)
	for i := 0; i < 6; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw := bytes.Clone(microdescriptor[:bytes.Index(microdescriptor, []byte("id ed25519 "))])
		if other, ok := family[i]; ok {
			related := sha1.Sum([]byte(fmt.Sprintf("test-only relay %d", other)))
			raw = fmt.Appendf(raw, "family $%X\n", related)
		}
		raw = fmt.Appendf(raw, "id ed25519 %s\n", base64.RawStdEncoding.EncodeToString(pub))
		hash := sha256.Sum256(raw)
		digest := base64.RawStdEncoding.EncodeToString(hash[:])
		mds[digest] = raw
		relayID := sha1.Sum([]byte(fmt.Sprintf("test-only relay %d", i)))
		flags := "Fast Running Stable Valid V2Dir"
		if i < 2 {
			flags += " Guard"
		} else if i >= 4 {
			flags += " Exit"
		}
		proto := "HSIntro=4 HSRend=2"
		if hsdirs[i] {
			flags += " HSDir"
			proto += " HSDir=2"
		}
		fmt.Fprintf(&body, "r relay%d %s %s 10.%d.0.1 9001 0\ns %s\npr %s\nw Bandwidth=1000\nm %s\n", i, base64.RawStdEncoding.EncodeToString(relayID[:]), stamp(-time.Hour), i, flags, proto, digest)
	}
	body.WriteString("directory-footer\ndirectory-signature ")
	digest := sha256.Sum256(body.Bytes())
	fmt.Fprintf(&body, "sha256 %X %X\n%s", id, skID, pemObject("SIGNATURE", sign(signing, digest[:])))
	c, err := common.AuthenticateConsensus(body.Bytes(), []byte(cert), [][20]byte{id}, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.OwnAuthenticatedHydration(mds)
	if err != nil {
		t.Fatalf("verified fixture hydration: %v", err)
	}
	if err := c.Validate(); err != nil || !c.TrustedHydrated() {
		t.Fatalf("hydrated fixture: %v", err)
	}
	return c
}
