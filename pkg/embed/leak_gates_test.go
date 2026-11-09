package embed

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestLeakGatesClientCloseCycles(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for i := 0; i < 256; i++ {
		b := &stubBuilder{}
		c := newTestClient(t, b)
		if err := c.Close(); err != nil {
			t.Fatalf("close cycle %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+32 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+32 {
		t.Fatalf("goroutines grew from %d to %d", baseline, got)
	}
}

func TestLeakGatesClientCloseOwnership(t *testing.T) {
	b := &pendingBuild{started: make(chan struct{}, 4)}
	c := newTestClient(t, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := c.DialContext(ctx, "tcp", "example.com:80")
		done <- err
	}()

	select {
	case <-b.started:
	case err := <-done:
		t.Fatalf("operation ended before circuit construction: %v", err)
	case <-ctx.Done():
		t.Fatal("operation did not reach circuit construction")
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pending operation returned %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not cancel pending operation")
	}
}
