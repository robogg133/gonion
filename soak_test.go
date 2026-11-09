package gonion

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestSoakBoundedCircuitLoop(t *testing.T) {
	conn := newTestConn(t)
	destroys := make(chan testDestroy, 32)
	serveFast(t, conn, false, destroys)
	baselineGoroutines := runtime.NumGoroutine()
	baselineRegistry := conn.circuits.Len()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		circuit, err := conn.NewFastCircuitContext(ctx)
		cancel()
		if err != nil {
			t.Fatalf("soak build failed: %v", err)
		}
		if err := circuit.Close(); err != nil {
			t.Fatalf("soak close failed: %v", err)
		}
	}

	pollDeadline := time.Now().Add(5 * time.Second)
	for (conn.circuits.Len() != baselineRegistry || runtime.NumGoroutine() > baselineGoroutines+16) && time.Now().Before(pollDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := conn.circuits.Len(); got != baselineRegistry {
		t.Fatalf("registry did not return to baseline: %d vs %d", got, baselineRegistry)
	}
	if got := runtime.NumGoroutine(); got > baselineGoroutines+16 {
		t.Fatalf("goroutines did not return to baseline: %d vs %d", got, baselineGoroutines)
	}
}
