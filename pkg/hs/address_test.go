package hs

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

// real spec example addresses (rend-spec §ONIONADDRESS). The 2nd one in the
// spec is illustrative and not checksum-valid, so only the valid two are used.
// Real example addresses from rend-spec §ONIONADDRESS. The middle one in the
// spec is illustrative and not checksum-valid; the first and third decode.
var specAddrs = []string{
	"pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
	"xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion",
}

func TestOnionRoundtrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := EncodeOnionAddr(pub)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseOnionAddr(addr)
	if err != nil {
		t.Fatalf("decode %q: %v", addr, err)
	}
	if !bytes.Equal(parsed.PublicKey, pub) {
		t.Fatalf("pubkey mismatch")
	}
	if parsed.String() != addr {
		t.Fatalf("re-encode %q != %q", parsed.String(), addr)
	}
}

func TestSpecExampleAddresses(t *testing.T) {
	for _, a := range specAddrs {
		p, err := ParseOnionAddr(a)
		if err != nil {
			t.Fatalf("%q: %v", a, err)
		}
		if p.String() != a {
			t.Fatalf("%q re-encoded to %q", a, p.String())
		}
	}
}

func TestParseBadAddresses(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	good, _ := EncodeOnionAddr(pub)

	// Tamper a base32 body char, keep the .onion suffix: must be a checksum
	// failure, not a length/format error.
	tampered := good[:len(good)-len(hsSuffix)]
	if tampered[len(tampered)/2] == 'a' {
		b := []byte(tampered)
		b[len(b)/2] = 'b'
		tampered = string(b)
	} else {
		b := []byte(tampered)
		b[len(b)/2] = 'a'
		tampered = string(b)
	}
	if _, err := ParseOnionAddr(tampered + hsSuffix); err == nil {
		t.Fatal("expected failure on tampered address")
	} else if !errors.Is(err, errChecksum) {
		t.Fatalf("tampered address: got %v, want errChecksum", err)
	}

	if _, err := ParseOnionAddr("not-an-onion"); !errors.Is(err, errInvalidAddr) {
		t.Fatalf("non-onion: got %v, want errInvalidAddr", err)
	}
	if _, err := ParseOnionAddr("short.onion"); !errors.Is(err, errInvalidAddr) {
		t.Fatalf("short input: got %v, want errInvalidAddr", err)
	}
}

func TestHasTorsionRejectsLowOrder(t *testing.T) {
	// A known 8-torsion point (small order) must be flagged.
	lowOrder, _ := hex.DecodeString(
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
	if !hasTorsion(lowOrder) {
		t.Fatal("expected low-order point to be flagged")
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	if hasTorsion(pub) {
		t.Fatal("random valid ed25519 point flagged as torsion")
	}
}
