package common

import (
	"bytes"
	"testing"
)

// Fuzz targets for V5.2 attack-surface evidence (dir-spec consensus text).
// Provenance: seeds are minimal hand-written ns documents mirroring
// consensus_verify_test.go TestConsensusAuthorityQuorum and testutil's
// signed microdesc fixture shape. They exercise structural parsing only;
// signature/quorum verification (AuthenticateConsensus) is not claimed here.
// No crasher has been minimized yet; any new corpus entry from a campaign
// must be added as a seed with its finding ID noted in this header.

func FuzzParseConsensus(f *testing.F) {
	// Seed 0: minimal valid ns header/footer (mirrors TestConsensusAuthorityQuorum ns body).
	f.Add([]byte("network-status-version 3\n" +
		"vote-status consensus\n" +
		"valid-after 2014-01-01 00:00:00\n" +
		"fresh-until 2014-01-01 02:00:00\n" +
		"valid-until 2014-01-01 03:00:00\n" +
		"directory-footer\n"))
	// Seed 1: microdesc flavor + params line (dir-spec 3.4.1 params bounds).
	f.Add([]byte("network-status-version 3 microdesc\n" +
		"vote-status consensus\n" +
		"valid-after 2014-01-01 00:00:00\n" +
		"fresh-until 2014-01-01 02:00:00\n" +
		"valid-until 2014-01-01 03:00:00\n" +
		"params bwweightscale=10000 hsdir-interval=65536\n" +
		"directory-footer\n"))
	// Seed 2: router block with r/s/pr/w/m lines (testutil shape, truncated).
	f.Add([]byte("network-status-version 3 microdesc\n" +
		"vote-status consensus\n" +
		"valid-after 2014-01-01 00:00:00\n" +
		"fresh-until 2014-01-01 02:00:00\n" +
		"valid-until 2014-01-01 03:00:00\n" +
		"r relay0 AAAA 2014-01-01 00:00:00 10.0.0.1 9001 0\n" +
		"s Fast Running Stable Valid V2Dir\n" +
		"pr HSIntro=4 HSRend=2\n" +
		"w Bandwidth=1000\n" +
		"m AAAA\n" +
		"directory-footer\n"))
	// Seed 3: empty + junk (rejection path coverage).
	f.Add([]byte{})
	f.Add([]byte("network-status-version 3\n"))
	f.Add([]byte("params bwweightscale=99999999999999999999\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		// Bound the fuzz input to the production bound; larger inputs are
		// already rejected as oversize and would only waste fuzzer cycles.
		if len(b) > MaxConsensusSize {
			return
		}
		c, err := ParseConsensus(bytes.NewReader(b))
		if err != nil {
			return
		}
		// Exercise derived helpers that must not panic on parsed state:
		// parameter bounds are clamped in Consensus.Parameter (dir-spec 3.4.1).
		_ = c.Parameter("bwweightscale", 10000, 1, 10000)
		_ = c.Parameter("hsdir-interval", 65536, 1, 1<<24)
		_ = c.Parameter("fake-param", 7, 0, 100)
		if _, err := FormatConsensus(c); err != nil {
			// Format re-parses the signed document; a structural parse that
			// does not round-trip is an invariant failure worth surfacing.
			t.Fatalf("parsed consensus does not format: %v", err)
		}
		// Clone must preserve parsed sizes without panicking.
		_ = c.Clone()
	})
}

func FuzzParseConsensusParameters(f *testing.F) {
	// Direct coverage of the params line without a full valid document.
	f.Add([]byte("bwweightscale=10000 hsdir-interval=65536"))
	f.Add([]byte("bwweightscale=-5 hsdir-interval=0"))
	f.Add([]byte("bwweightscale=99999999999999999999"))
	f.Add([]byte{})
	f.Add([]byte("unknownparam=123"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return
		}
		// Build a minimal consensus and assign params via text parsing
		// path: route through ParseConsensus header handling by embedding
		// the fuzz bytes as a params line in an otherwise valid header.
		doc := "network-status-version 3\n" +
			"vote-status consensus\n" +
			"valid-after 2014-01-01 00:00:00\n" +
			"fresh-until 2014-01-01 02:00:00\n" +
			"valid-until 2014-01-01 03:00:00\n" +
			"params " + string(b) + "\n" +
			"directory-footer\n"
		c, err := ParseConsensus(bytes.NewReader([]byte(doc)))
		if err != nil {
			return
		}
		for name := range c.Params {
			_ = c.Parameter(name, 1, 0, 1<<31-1)
		}
	})
}

func FuzzPortsLine(f *testing.F) {
	// Covers dir-spec exit-policy lines used in both router and microdesc
	// parsing (pkg/common/ports.go).
	f.Add([]byte("accept 1-65535"))
	f.Add([]byte("reject 1-1023"))
	f.Add([]byte("accept 0-70000"))
	f.Add([]byte{})
	f.Add([]byte("*:443"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return
		}
		var p Ports
		_ = ParseDirectoryPorts(&p, string(b))
		_ = ParsePortsLine(&Ports{}, string(b))
		_ = FormatPortsPolicy(&p)
	})
}
