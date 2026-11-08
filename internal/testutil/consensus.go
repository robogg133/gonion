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
	"crypto/sha3"
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

type consensusOptions struct {
	hsdirs map[int]bool
	family map[int]int
	// srv signs explicit shared random values into the body (dir-spec.txt
	// shared-rand-current-value / shared-rand-previous-value), instead of
	// patching them into the authenticated view afterwards.
	srv *[2][32]byte
	// relaySeed derives the six relay ed25519 identities deterministically
	// (sha3("test relay", seed, i)) so HSDir ring membership is reproducible.
	relaySeed *[32]byte
	// hsdirInterval signs hsdir_interval in consensus params (0 = default).
	hsdirInterval uint64
	// stamps overrides valid-after/valid-until; fresh-until stays one hour
	// after valid-after, giving a one-hour voting interval.
	validAfter, validUntil time.Time
}

// Consensus signs a small test network for the supplied time, then verifies it
// with an explicitly pinned test authority and hash-checked microdescriptors.
// No production authority, authentication marker, or clock check is overridden.
func Consensus(t testing.TB, now time.Time) *common.Consensus {
	return consensus(t, now, consensusOptions{})
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
	return consensus(t, now, consensusOptions{hsdirs: hsdirs})
}

// ConsensusWithFamily signs mutual family declarations in the descriptor
// digests for two relays before verifying and hydrating the directory.
func ConsensusWithFamily(t testing.TB, now time.Time, a, b int) *common.Consensus {
	t.Helper()
	if a < 0 || a >= 6 || b < 0 || b >= 6 || a == b {
		t.Fatal("invalid test family indices")
	}
	return consensus(t, now, consensusOptions{family: map[int]int{a: b, b: a}})
}

// ConsensusWithSRV signs explicit SRVs into the authenticated consensus body;
// a non-nil relaySeed also fixes the relay identities. Neither value modifies
// an already-verified view, so trust semantics stay identical to Consensus.
func ConsensusWithSRV(t testing.TB, now time.Time, current, previous [32]byte, relaySeed *[32]byte, indices ...int) *common.Consensus {
	t.Helper()
	hsdirs := make(map[int]bool, len(indices))
	for _, index := range indices {
		if index < 0 || index >= 6 {
			t.Fatal("test HSDir index out of range")
		}
		hsdirs[index] = true
	}
	return consensus(t, now, consensusOptions{hsdirs: hsdirs, srv: &[2][32]byte{current, previous}, relaySeed: relaySeed})
}

// EpochOptions states all fixture freedoms the H3.1 rollover tests need inside
// the signed document: explicit validity stamps (both epochs stay live over
// the run clock), a signed SRV pair, deterministic relay identities, HSDir
// flags, and a signed hsdir_interval.
type EpochOptions struct {
	ValidAfter        time.Time
	ValidUntil        time.Time
	HsdirInterval     uint64 // minutes; 0 keeps the default 1440
	RelaySeed         *[32]byte
	Current, Previous [32]byte
	HSDirs            []int
}

// ConsensusEpoch signs a consensus from one explicit validity interval for
// tests that compare adjacent SRV/period epochs offline.
func ConsensusEpoch(t testing.TB, o EpochOptions) *common.Consensus {
	t.Helper()
	opts := consensusOptions{srv: &[2][32]byte{o.Current, o.Previous}, relaySeed: o.RelaySeed, hsdirInterval: o.HsdirInterval, validAfter: o.ValidAfter, validUntil: o.ValidUntil}
	for _, index := range o.HSDirs {
		if index < 0 || index >= 6 {
			t.Fatal("test HSDir index out of range")
		}
		opts.hsdirs = make(map[int]bool, len(o.HSDirs))
	}
	opts.hsdirs = make(map[int]bool, len(o.HSDirs))
	for _, index := range o.HSDirs {
		opts.hsdirs[index] = true
	}
	return consensus(t, o.ValidAfter, opts)
}

func consensus(t testing.TB, now time.Time, o consensusOptions) *common.Consensus {
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

	validAfter, validUntil := now.Add(-time.Hour), now.Add(2*time.Hour)
	if !o.validAfter.IsZero() {
		validAfter = o.validAfter
	}
	if !o.validUntil.IsZero() {
		validUntil = o.validUntil
	}
	freshUntil := validAfter.Add(time.Hour)
	if !freshUntil.Before(validUntil) {
		t.Fatal("test validity stamps do not leave a one-hour voting interval")
	}
	stamped := func(t time.Time) string { return t.UTC().Format(common.CONSENSUS_DATE_FORMAT) }

	var body bytes.Buffer
	fmt.Fprintf(&body, "network-status-version 3 microdesc\nvote-status consensus\nvalid-after %s\nfresh-until %s\nvalid-until %s\n", stamped(validAfter), stamped(freshUntil), stamped(validUntil))
	if o.srv != nil {
		encode := func(b [32]byte) string { return base64.StdEncoding.EncodeToString(b[:]) }
		fmt.Fprintf(&body, "shared-rand-current-value 0 %s\n", encode(o.srv[0]))
		fmt.Fprintf(&body, "shared-rand-previous-value 0 %s\n", encode(o.srv[1]))
	}
	if o.hsdirInterval != 0 {
		fmt.Fprintf(&body, "params hsdir_interval=%d\n", o.hsdirInterval)
	}
	mds := make(map[string][]byte)
	for i := 0; i < 6; i++ {
		var pub ed25519.PublicKey
		if o.relaySeed != nil {
			digest := sha3.Sum256(append(append([]byte("test relay "), o.relaySeed[:]...), byte(i)))
			pub = ed25519.NewKeyFromSeed(digest[:]).Public().(ed25519.PublicKey)
		} else {
			key, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pub = priv.Public().(ed25519.PublicKey)
			_ = key
		}
		raw := bytes.Clone(microdescriptor[:bytes.Index(microdescriptor, []byte("id ed25519 "))])
		if other, ok := o.family[i]; ok {
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
		if o.hsdirs[i] {
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
	if o.srv != nil {
		if !c.HasSharedCurrentValue || !c.HasSharedPreviousValue || c.SharedCurrentValue != o.srv[0] || c.SharedPreviousValue != o.srv[1] {
			t.Fatal("signed SRVs missing from the authenticated consensus")
		}
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
