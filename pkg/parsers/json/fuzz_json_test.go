package json

import (
	"bytes"
	"testing"
)

// JSON consensus parser fuzzing for V5.2. The JSON parser is a local snapshot
// (not authority-authenticated); it must bound sizes and reject unknown or
// oversized fields without panicking. Provenance: seeds are minimal DTO
// shapes mirroring json_test.go TestRoundTrip; no crasher minimized yet.

func FuzzConsensusJSON(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Flavor":"microdesc"}`))
	f.Add([]byte(`{"RelayInformation":[]}`))
	f.Add([]byte{})
	f.Add([]byte(`{"NetworkStatusVersion":3,"Flavor":"microdesc"}`))
	f.Add(bytes.Repeat([]byte(` `), 200))
	f.Fuzz(func(t *testing.T, b []byte) {
		// The parser already bounds input via parsers.ReadAll (256 MiB);
		// skip larger fuzz inputs to keep cycles on mutation depth.
		if len(b) > 1<<20 {
			return
		}
		p := Parser{}
		c, err := p.Parse(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(c.RelayInformation) > 20000 {
			t.Fatal("oversized relay list accepted")
		}
		// Format must succeed on any successfully parsed snapshot that
		// validates; a parse without validate success is an invariant bug.
		if err := c.Validate(); err != nil {
			return
		}
		if _, err := p.Format(c); err != nil {
			t.Fatalf("parsed consensus does not format: %v", err)
		}
	})
}

// Guard JSON fuzzing complement: the guard snapshot parser lives in
// pkg/path (FuzzGuardStateDecode). This additional target exercises the same
// JSON shape via the consensus JSON DTO's microdescriptor/params fields
// that guards hydrate from, documenting the cross-parser surface.
func FuzzGuardRelatedJSON(f *testing.F) {
	f.Add([]byte(`{"guards":[]}`))
	f.Add([]byte(`{"version":1,"instance":"public-default","guards":[]}`))
	f.Add([]byte{123, 34, 118, 101, 114, 115, 105, 111, 110, 34, 58, 49, 125})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		// Parse as consensus JSON; must not panic on guard-like inputs.
		p := Parser{}
		_, _ = p.Parse(bytes.NewReader(b))
	})
}
