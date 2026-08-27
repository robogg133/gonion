package usual

import (
	"bytes"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

func TestParseFixtureCount(t *testing.T) {
	data, err := os.ReadFile("../../../internal/tests/consensus-microdesc.txt")
	if err != nil {
		t.Fatal(err)
	}

	c, err := (Parser{}).Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Count(data, []byte("\nr ")) + boolToInt(bytes.HasPrefix(data, []byte("r ")))
	if got := len(c.RelayInformation); got != want {
		t.Fatalf("relay count = %d, want %d", got, want)
	}
	if c.ValidAfter.IsZero() || c.ValidUntil.Before(c.ValidAfter) {
		t.Fatalf("bad validity window: after=%v until=%v", c.ValidAfter, c.ValidUntil)
	}
	first := c.RelayInformation[0]
	if first.Nickname == "" || first.ORPort == 0 || first.IPLevel == 0 {
		t.Fatalf("first router poorly parsed: %+v", first)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func protoBits(nums ...uint8) common.VersionValue {
	var v common.VersionValue
	for _, n := range nums {
		v.SetValue(n, true)
	}
	return v
}

func TestRoundTrip(t *testing.T) {
	c := &common.Consensus{
		NetowrkStatusVersion: 3,
		ValidAfter:           time.Date(2026, 1, 30, 22, 0, 0, 0, time.UTC),
		FreshUntil:           time.Date(2026, 1, 30, 23, 0, 0, 0, time.UTC),
		ValidUntil:           time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC),
		SharedCurrentValue:   [32]byte{1, 2, 3},
		BandWidthWeight:      common.BandWidthWeight{Wbd: 55, Wgg: 66},
		RelayInformation: []common.RouterStatus{
			{
				Nickname:              "relay1",
				NodeID:                [20]byte{9, 9, 9},
				Ipv4Addr:              "1.2.3.4",
				IPLevel:               0x20000102, // computed by common.IPLevel for 1.2.3.4
				ORPort:                9001,
				DirPort:               9030,
				BandWidth:             102400,
				Ipv6Addr:              "[2001:db8::1]:9001",
				MicrodescriptorDigest: "abc",
				ProtoVersions:         common.Proto{Link: protoBits(4, 5), Relay: protoBits(2, 4)},
				StatusFlags:           [common.FLAG_ARRAY_LENGTH + 1]bool{0: true, 2: true, 10: true},
			},
			{
				Nickname: "relay2",
				NodeID:   [20]byte{1},
				Ipv4Addr: "5.6.7.8",
				IPLevel:  0x20000506,
				ORPort:   443,
				DirPort:  0,
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
		t.Fatalf("round-trip mismatch:\ngot  %+v\nwant %+v\n--- text ---\n%s", got, c, b)
	}
}