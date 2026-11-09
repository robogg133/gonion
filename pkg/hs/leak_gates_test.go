package hs

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/hs/capi"
)

func TestLeakGatesListenerBlockedAccept(t *testing.T) {
	baseline := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &Listener{ctx: ctx, cancel: cancel, incoming: make(chan net.Conn, 1)}

	done := make(chan error, 1)
	go func() { _, err := l.Accept(); done <- err }()
	time.Sleep(20 * time.Millisecond)

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after close = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Accept did not return")
	}

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+16 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+16 {
		t.Fatalf("goroutines grew from %d to %d", baseline, got)
	}
}

func TestLeakGatesListenerClosePreservesAccepted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	circCtx, closeCirc := context.WithCancel(context.Background())
	defer closeCirc()
	rp := &lifecycleCircuit{ctx: circCtx, cancel: closeCirc}
	l := &Listener{ctx: ctx, cancel: cancel, incoming: make(chan net.Conn, 2), rendezvous: map[capi.ServiceCirc]struct{}{rp: {}}}

	accepted, peer := net.Pipe()
	defer accepted.Close()
	defer peer.Close()
	pending, pendingPeer := net.Pipe()
	defer pendingPeer.Close()

	l.incoming <- accepted
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	l.incoming <- pending
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if !rp.stopped.Load() || circCtx.Err() != nil {
		t.Fatal("Close killed accepted circuit or did not stop acceptance")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want %v", err, net.ErrClosed)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := peer.Write([]byte{42}); done <- err }()
	if n, err := conn.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("accepted stream closed: %d %v", n, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = pendingPeer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := pendingPeer.Write([]byte{1}); err == nil {
		t.Fatal("pending connection survived Close")
	}
}

func TestLeakGatesListenerShutdownOwnership(t *testing.T) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	circCtx, closeCirc := context.WithCancel(context.Background())
	defer closeCirc()
	rp := &lifecycleCircuit{ctx: circCtx, cancel: closeCirc}
	l := &Listener{ctx: ctx, cancel: cancel, incoming: make(chan net.Conn, 1), rendezvous: map[capi.ServiceCirc]struct{}{rp: {}}}

	accepted, peer := net.Pipe()
	defer peer.Close()
	l.incoming <- accepted
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = l.Shutdown()
	}()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = peer.Write([]byte{7})
	_, _ = conn.Read(make([]byte, 1))
	wg.Wait()
	_ = conn.Close()
}
