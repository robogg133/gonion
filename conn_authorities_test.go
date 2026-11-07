package gonion

import (
	"testing"
)

func TestSetTrustedAuthorities(t *testing.T) {
	valid := [][20]byte{{1}, {2}, {3}}
	c := &Conn{}
	if err := c.SetTrustedAuthorities(valid); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}
	if got := len(c.trustedAuthorities); got != 3 {
		t.Fatalf("stored %d pins", got)
	}
	second := &Conn{}
	type pinCase struct {
		name string
		pins [][20]byte
	}
	for _, tc := range []pinCase{
		{name: "empty", pins: nil},
		{name: "zero pin", pins: [][20]byte{{1}, {}}},
		{name: "duplicate", pins: [][20]byte{{1}, {1}}},
	} {
		if err := second.SetTrustedAuthorities(tc.pins); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	// Priority contract: one recorded override can never be silently replaced.
	if err := c.SetTrustedAuthorities(valid); err == nil {
		t.Fatal("double set accepted")
	}
}
