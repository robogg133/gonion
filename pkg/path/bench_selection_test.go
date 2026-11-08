package path

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
)

// O6.1 path-selection baseline. Offline fixture consensus from testutil
// (6 relays, signed + hydrated). No network or public relays are used.
// Selection still enforces authenticated live consensus (path-spec).

func trustedBenchConsensus(b *testing.B) *common.Consensus {
	b.Helper()
	input := testutil.Consensus(b, time.Now())
	c, err := input.OwnAuthenticatedHydration(input.Microdescriptors)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

func BenchmarkSelectRandomCircuit(b *testing.B) {
	cns := trustedBenchConsensus(b)
	// Trusted snapshot construction is outside the timer; each iteration
	// allocates a fresh Selector to avoid reusing selection state.
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sel := New(cns, false)
		if err := sel.SelectRandomCircuit(3, 80); err != nil {
			b.Fatal(err)
		}
		if len(sel.Circuit()) != 3 {
			b.Fatalf("path length %d", len(sel.Circuit()))
		}
	}
}

func BenchmarkSelectRandomCircuitLongLive(b *testing.B) {
	cns := trustedBenchConsensus(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sel := New(cns, true)
		if err := sel.SelectRandomCircuit(3, 443); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSelectHSRelayIntro(b *testing.B) {
	cns := trustedBenchConsensus(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sel := New(cns, false)
		if _, err := sel.SelectHSRelay(true); err != nil {
			b.Fatal(err)
		}
	}
}

// GuardManager selection against durable in-memory persistence. Each iteration
// selects and closes a lease; persistence callbacks clone via bytes.Clone to
// reflect the durable-snapshot contract without touching disk.
func BenchmarkGuardManagerSelect(b *testing.B) {
	cns := trustedBenchConsensus(b)
	var stored []byte
	persist := GuardPersistence{
		Load: func(context.Context) ([]byte, error) { return bytes.Clone(stored), nil },
		Save: func(_ context.Context, data []byte) error {
			stored = bytes.Clone(data)
			return nil
		},
	}
	m, err := NewGuardManager(context.Background(), persist)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease, err := m.Select(context.Background(), cns, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err := lease.Succeeded(context.Background()); err != nil {
			b.Fatal(err)
		}
		if err := lease.Wait(context.Background()); err != nil {
			b.Fatal(err)
		}
		lease.Close()
	}
}
