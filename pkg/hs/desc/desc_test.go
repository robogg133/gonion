package desc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"testing"

	"github.com/robogg133/gonion/pkg/lspec"
)

// buildIntroBlock encodes one introduction point in the binary format the
// descriptor uses (rend-spec-v3 §FMT_INTRO1 inner listing):
//
//	ONION_KEY_TYPE(1) ONION_KEY_LEN(2) ONION_KEY(32)
//	AUTH_KEY_TYPE(1)  AUTH_KEY_LEN(2)  AUTH_KEY(32)
//	N_EXTENSIONS(1) [exts]
//	N_LINK_SPECS(1) [TYPE(1) LEN(1) DATA ...]
func buildIntroBlock(t *testing.T, onionKey, authKey []byte, specs []lspec.Lspec) []byte {
	t.Helper()
	var b bytes.Buffer
	// onion key
	b.WriteByte(1)
	b.WriteByte(0)
	b.WriteByte(32)
	b.Write(onionKey)
	// auth key
	b.WriteByte(2)
	b.WriteByte(0)
	b.WriteByte(32)
	b.Write(authKey)
	// extensions: none
	b.WriteByte(0)
	// link specifiers
	b.WriteByte(byte(len(specs)))
	for _, s := range specs {
		raw, err := s.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		b.WriteByte(s.Type())
		b.WriteByte(byte(len(raw)))
		b.Write(raw)
	}
	return b.Bytes()
}

func TestParseDescriptor(t *testing.T) {
	onionKey := bytes.Repeat([]byte{0x11}, 32)
	authKey := bytes.Repeat([]byte{0x22}, 32)

	// IPv4 link spec: 6-byte body.
	ipSpec := mustLspec(t, lspec.LSTYPE_IPV4, []byte{0x7f, 0, 0, 1, 0x1f, 0x90}) // 127.0.0.1:8080
	edSpec := mustLspec(t, lspec.LSTYPE_ED25519_ID, bytes.Repeat([]byte{0x33}, 32))

	block := buildIntroBlock(t, onionKey, authKey, []lspec.Lspec{ipSpec, edSpec})

	body := "version 3\n" +
		"lifetime 180\n" +
		"introduction-points auth-key\n" +
		base64.StdEncoding.EncodeToString(block) + "\n" +
		"\nsignature\n"

	desc, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if desc.Version != 3 {
		t.Fatalf("version = %d, want 3", desc.Version)
	}
	if desc.LifetimeSeconds != 180 {
		t.Fatalf("lifetime = %d, want 180", desc.LifetimeSeconds)
	}
	if len(desc.IntroPoints) != 1 {
		t.Fatalf("intro points = %d, want 1", len(desc.IntroPoints))
	}
	ip := desc.IntroPoints[0]
	if !bytes.Equal(ip.OnionKey, onionKey) {
		t.Fatalf("onion key mismatch")
	}
	if !bytes.Equal(ip.AuthKey, authKey) {
		t.Fatalf("auth key mismatch")
	}
	if len(ip.LinkSpecs) != 2 {
		t.Fatalf("link specs = %d, want 2", len(ip.LinkSpecs))
	}
	// Verify the ipv4 spec decoded to 127.0.0.1:8080 using lspec directly.
	var gotIP string
	var gotPort uint16
	for _, s := range ip.LinkSpecs {
		if s.Type() == lspec.LSTYPE_IPV4 {
			raw, _ := s.Bytes()
			gotIP = net.IP(raw[:4]).String()
			gotPort = uint16(raw[4])<<8 | uint16(raw[5])
		}
	}
	if gotIP != "127.0.0.1" || gotPort != 8080 {
		t.Fatalf("ipv4 spec wrong: ip=%q port=%d", gotIP, gotPort)
	}
}

func TestParseNoIntroPoints(t *testing.T) {
	// Outer layer without intro points (e.g. superencrypted inner). Parse must
	// not fail, just return an empty intro list.
	body := "version 3\nlifetime 180\nsignature\n"
	desc, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(desc.IntroPoints) != 0 {
		t.Fatalf("expected no intro points, got %d", len(desc.IntroPoints))
	}
}

func mustLspec(t *testing.T, typ uint8, body []byte) lspec.Lspec {
	t.Helper()
	s, err := lspec.FromWire(typ, body)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ensure ed25519 import is exercised by the test build path.
var _ = ed25519.PublicKeySize
