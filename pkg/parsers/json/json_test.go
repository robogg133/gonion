package json

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

func TestRoundTrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := priv.PublicKey()

	c := &common.Consensus{
		NetowrkStatusVersion: 3,
		ValidAfter:           time.Date(2026, 1, 30, 22, 0, 0, 0, time.UTC),
		FreshUntil:           time.Date(2026, 1, 30, 23, 0, 0, 0, time.UTC),
		ValidUntil:           time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC),
		SharedCurrentValue:   [32]byte{1, 2, 3},
		BandWidthWeight:      common.BandWidthWeight{Wbe: 1, Wgm: 2},
		RelayInformation: []common.RouterStatus{
			{
				Nickname:              "relay1",
				NodeID:                [20]byte{9, 9, 9},
				Ipv4Addr:              "1.2.3.4",
				IPLevel:               0x20000102,
				ORPort:                9001,
				DirPort:               9030,
				BandWidth:             102400,
				Ipv6Addr:              "[2001:db8::1]:9001",
				MicrodescriptorDigest: "abc",
				ProtoVersions: common.Proto{Link: 0b11000, Relay: 0b10100},
				StatusFlags:   [common.FLAG_ARRAY_LENGTH + 1]bool{0: true, 5: true},
				OnionKey:      []byte("fake rsa bytes"),
				NTorOnionKey:  key,
				IdEd25519:     []byte{0xde, 0xad},
				Family:        []common.Family{{Digest: []byte{1, 2}}, {Nickname: "nick"}},
				Familys:       []*common.FamilyIDs{{Kind: "AAP", Value: []byte{0xbe, 0xef}}},
			},
		},
	}
	c.RelayInformation[0].Ports.SetPort(22, true)
	c.RelayInformation[0].Ports.SetPort(443, true)

	b, err := (Parser{}).Format(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (Parser{}).Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, b)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round-trip mismatch:\ngot  %+v\nwant %+v", got, c)
	}
}