package common_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
)

// O6.1 baselines for consensus parse/hydration and microdescriptors.
// All fixtures are offline and deterministic: testutil signs a small
// 6-relay microdesc consensus with test authority keys, verified against a
// pinned test identity (dir-spec 3.x). No public consensus or network is used.
// Benchmarks measure testutil.Consensus outside the timer.

func benchParsedConsensus(b *testing.B) ([]byte, *common.Consensus) {
	b.Helper()
	now := time.Now()
	c := testutil.Consensus(b, now)
	raw := bytes.Clone(c.RawDocument)
	parsed, err := common.ParseConsensus(bytes.NewReader(raw))
	if err != nil {
		b.Fatal(err)
	}
	return raw, parsed
}

func BenchmarkParseConsensus(b *testing.B) {
	raw, _ := benchParsedConsensus(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := common.ParseConsensus(bytes.NewReader(raw))
		if err != nil {
			b.Fatal(err)
		}
		_ = c
	}
}

func BenchmarkOwnAuthenticatedHydration(b *testing.B) {
	// Hydration requires an authenticated (trusted) source, so the base is
	// the testutil view itself; parsing is benchmarked separately.
	source := testutil.Consensus(b, time.Now())
	// Deep-copy the descriptor map so each hydration sees pristine input.
	descriptors := make(map[string][]byte, len(source.Microdescriptors))
	for k, v := range source.Microdescriptors {
		descriptors[k] = bytes.Clone(v)
	}
	if _, err := source.OwnAuthenticatedHydration(descriptors); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hydrated, err := source.OwnAuthenticatedHydration(descriptors)
		if err != nil {
			b.Fatal(err)
		}
		_ = hydrated
	}
}

func BenchmarkConsensusClone(b *testing.B) {
	c := testutil.Consensus(b, time.Now())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Clone()
	}
}

func BenchmarkConsensusParameter(b *testing.B) {
	c := testutil.Consensus(b, time.Now())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Parameter("bwweightscale", 10000, 1, 10000)
		_ = c.Parameter("hsdir-interval", 65536, 1, 1<<24)
	}
}

func BenchmarkFormatConsensus(b *testing.B) {
	// FormatConsensus re-parses the signed document (see consensus_parse.go);
	// this benchmark therefore measures parse+validate+copy, not a pure serializer.
	c := testutil.Consensus(b, time.Now())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := common.FormatConsensus(c)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

func BenchmarkParseMicrodescriptor(b *testing.B) {
	c := testutil.Consensus(b, time.Now())
	if len(c.RelayInformation) == 0 {
		b.Fatal("empty fixture consensus")
	}
	digest := c.RelayInformation[0].MicrodescriptorDigest
	raw, ok := c.Microdescriptors[digest]
	if !ok {
		b.Fatal("missing microdescriptor fixture")
	}
	raw = bytes.Clone(raw)
	if _, err := common.ParseMicrodescriptor(raw, digest); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m, err := common.ParseMicrodescriptor(raw, digest)
		if err != nil {
			b.Fatal(err)
		}
		_ = m
	}
}
