package gonion

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

func TestLeakGatesBuildCloseCycles(t *testing.T) {
	conn := newTestConn(t)
	destroys := make(chan testDestroy, 32)
	serveFast(t, conn, false, destroys)
	baseline := runtime.NumGoroutine()

	const cycles = 10000
	for i := 0; i < cycles; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		circuit, err := conn.NewFastCircuitContext(ctx)
		cancel()
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if err := circuit.Close(); err != nil {
			t.Fatalf("cycle %d close: %v", i, err)
		}
	}
	if got := conn.circuits.Len(); got != 0 {
		t.Fatalf("%d registry entries survived %d cycles", got, cycles)
	}

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+16 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+16 {
		t.Fatalf("goroutines grew from %d to %d after %d cycles", baseline, got, cycles)
	}
}

func TestLeakGatesSlowPeer(t *testing.T) {
	baseline := runtime.NumGoroutine()
	conn := newTestConn(t)
	serveFast(t, conn, true, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := conn.NewFastCircuitContext(ctx); err == nil {
		t.Fatal("silent peer did not fail the build")
	}
	if conn.circuits.Len() != 0 {
		t.Fatal("failed build left a registry entry")
	}

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+16 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+16 {
		t.Fatalf("goroutines grew from %d to %d after slow peer", baseline, got)
	}
}

func TestLeakGatesQueueSaturation(t *testing.T) {
	c := testServiceCircuit(t)
	for id := uint16(1); id <= 17; id++ {
		c.acceptIncomingBegin(&relay.BeginCell{StreamID: id, Addrport: ":80"}, 3)
	}
	if len(c.service.incoming) != 16 {
		t.Fatalf("incoming queue len = %d, want 16", len(c.service.incoming))
	}
	if c.streams.Get(17) != nil {
		t.Fatal("overflow stream was registered")
	}
	_ = c.StopAccepting()
}
