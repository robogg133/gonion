package embed

import (
	"context"
	"testing"
	"time"

	gonion "github.com/robogg133/gonion"
)

func TestPoolReaperOwnedByClientLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{conn: &gonion.Conn{}}
	done := make(chan struct{})
	go func() { c.reapLoop(ctx); close(done) }()
	select {
	case <-done:
		t.Fatal("pool reaper exited because original bootstrap link is unavailable")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pool reaper did not stop on client lifetime cancellation")
	}
}
