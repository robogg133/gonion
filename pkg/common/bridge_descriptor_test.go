package common

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// C Tor test_descriptors.inc, commit 3937194; unmodified signed descriptors.
//
//go:embed testdata/bridge-0.desc
var bridgeFixture0 []byte

//go:embed testdata/bridge-1.desc
var bridgeFixture1 []byte

var bridgeFixtureTime = time.Date(2020, 10, 13, 14, 0, 0, 0, time.UTC)

func bridgeFixtureID(t *testing.T, s string) [20]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		t.Fatal("invalid fixture identity")
	}
	return [20]byte(b)
}

func TestBridgeDescriptorTorFixtures(t *testing.T) {
	for i, tc := range []struct {
		raw            []byte
		hash, id, ntor string
	}{
		{bridgeFixture0, "24f1046bcfce4a65855baef00aa88f350af7a74bb1d45d68b3b1551eedeb40d6", "240320ECF589C1F4DC0B864B28AF811359CEFD86", "rrw3paBStz7xhguZJDdjl/Tcpqwgv4u37Zi1zJcVNFk"},
		{bridgeFixture1, "372129fee7e91fca29a6e092c565c502531331b56f1b4ef5afc93c639685cee0", "184929185A951CF2DDA7C3B01ACB32D7360CC4BF", "/vAbEzRKRi0j/0mrhyKBdNMxR56xnzl6fQvtHT/QcAE"},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if fmt.Sprintf("%x", sha256.Sum256(tc.raw)) != tc.hash {
				t.Fatal("fixture changed")
			}
			d, err := ParseBridgeDescriptor(tc.raw, bridgeFixtureID(t, tc.id), bridgeFixtureTime)
			if err != nil {
				t.Fatal(err)
			}
			ntor, _ := bridgeBase64(tc.ntor)
			if !bytes.Equal(d.Relay.NTorOnionKey.Bytes(), ntor) || d.Relay.ORPort != uint16(5001+i) || d.Relay.NodeID != bridgeFixtureID(t, tc.id) || !d.Expires.Equal(d.Published.Add(48*time.Hour)) {
				t.Fatal("incorrect descriptor fields")
			}
			if d.Relay.StatusFlags[FLAG_GUARD] || d.Relay.MicrodescriptorLoaded {
				t.Fatal("bridge fabricated consensus membership")
			}
			if _, err := ParseBridgeDescriptor(append(bytes.Clone(tc.raw), '\n', '\n'), d.Relay.NodeID, bridgeFixtureTime); err != nil {
				t.Fatalf("trailing blank lines: %v", err)
			}
		})
	}
}

func TestBridgeDescriptorItemBlankLines(t *testing.T) {
	// dir-spec 1.2 allows blank lines between items. Altering signed bytes must
	// fail signature verification, not the identity certificate position check.
	raw := bytes.Replace(bridgeFixture0, []byte("identity-ed25519\n"), []byte("\nidentity-ed25519\n"), 1)
	id := bridgeFixtureID(t, "240320ECF589C1F4DC0B864B28AF811359CEFD86")
	if _, err := ParseBridgeDescriptor(raw, id, bridgeFixtureTime); err == nil || !strings.Contains(err.Error(), "invalid Ed25519 signature") {
		t.Fatalf("blank line rejected before signature verification: %v", err)
	}
}

func TestBridgeDescriptorRejectsMalformedAndTampered(t *testing.T) {
	id := bridgeFixtureID(t, "240320ECF589C1F4DC0B864B28AF811359CEFD86")
	for name, raw := range map[string][]byte{
		"truncated":          bridgeFixture0[:80],
		"oversize":           bytes.Repeat([]byte("x"), MaxBridgeDescriptorSize+1),
		"duplicate":          bytes.Replace(bridgeFixture0, []byte("published "), []byte("ntor-onion-key AAAA\npublished "), 1),
		"sign bit":           bytes.Replace(bridgeFixture0, []byte("crosscert 0"), []byte("crosscert 2"), 1),
		"ntor signature":     bytes.Replace(bridgeFixture0, []byte("AQoABs2O"), []byte("AQoABs2P"), 1),
		"TAP signature":      bytes.Replace(bridgeFixture0, []byte("Mr8P5C"), []byte("Ar8P5C"), 1),
		"Ed signature":       bytes.Replace(bridgeFixture0, []byte("pVC4W6"), []byte("AVC4W6"), 1),
		"RSA signature":      bytes.Replace(bridgeFixture0, []byte("KHkPXB"), []byte("AHkPXB"), 1),
		"signed metadata":    bytes.Replace(bridgeFixture0, []byte("auth1@test.test"), []byte("auth2@test.test"), 1),
		"identity extension": bytes.Replace(bridgeFixture0, []byte("/2tF8UqpI68"), []byte("/2tF8UqpI69"), 1),
		"missing signature":  []byte(strings.Split(string(bridgeFixture0), "router-signature\n")[0]),
		"second descriptor":  append(bytes.Clone(bridgeFixture0), bridgeFixture1...),
		"CRLF":               bytes.ReplaceAll(bridgeFixture0, []byte("\n"), []byte("\r\n")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBridgeDescriptor(raw, id, bridgeFixtureTime); err == nil {
				t.Fatal("accepted invalid descriptor")
			}
		})
	}
	for _, now := range []time.Time{bridgeFixtureTime.Add(-24 * time.Hour), bridgeFixtureTime.Add(48 * time.Hour)} {
		if _, err := ParseBridgeDescriptor(bridgeFixture0, id, now); err == nil {
			t.Fatal("accepted invalid descriptor time")
		}
	}
	for _, pin := range [][20]byte{{}, {1}} {
		if _, err := ParseBridgeDescriptor(bridgeFixture0, pin, bridgeFixtureTime); err == nil {
			t.Fatal("accepted wrong pin")
		}
	}
}

func FuzzBridgeDescriptor(f *testing.F) {
	f.Add(bridgeFixture0)
	f.Add(bridgeFixture1)
	f.Fuzz(func(t *testing.T, raw []byte) {
		id := bridgeFixtureID(t, "240320ECF589C1F4DC0B864B28AF811359CEFD86")
		_, _ = ParseBridgeDescriptor(raw, id, bridgeFixtureTime)
	})
}
