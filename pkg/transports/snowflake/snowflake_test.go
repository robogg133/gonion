package snowflake

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPinnedConnectionCloseAndMetadata(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	pin := [20]byte{1}
	c := &pinnedConn{Conn: raw, identity: pin}
	if c.ExpectedRelayIdentity() != pin {
		t.Fatal("missing relay identity metadata")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestDefaultsAndPreDialValidation(t *testing.T) {
	a, b := DefaultOptions(), DefaultOptions()
	if a.BridgeFingerprint != DefaultBridgeFingerprint || len(a.FrontDomains) == 0 || len(a.ICEAddresses) == 0 || a.KeepLocalAddresses || a.Max != 1 || a.Log == nil {
		t.Fatal("incomplete defaults")
	}
	a.ICEAddresses[0], a.FrontDomains[0] = "changed", "changed"
	if b.ICEAddresses[0] == "changed" || b.FrontDomains[0] == "changed" {
		t.Fatal("shared mutable defaults")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DialContext(ctx, b); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, pin := range []string{"", "invalid", "0000000000000000000000000000000000000000"} {
		b.BridgeFingerprint = pin
		if _, err := DialContext(context.Background(), b); err == nil {
			t.Fatal("invalid pin accepted")
		}
	}
}

func TestDialContextClosesLateConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started, release := make(chan struct{}), make(chan struct{})
	raw, peer := net.Pipe()
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		_, err := dialContext(ctx, func() (net.Conn, error) { close(started); <-release; return raw, nil })
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late connection not closed")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("late close timed out")
	}
}

func TestDialContextTransfersOwnership(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := dialContext(ctx, func() (net.Conn, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = peer.Write([]byte{42}) }()
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil || buf[0] != 42 {
		t.Fatalf("completed connection tied to context: %v", err)
	}
	for _, fail := range []bool{false, true} {
		raw, peer := net.Pipe()
		_, err := dialContext(context.Background(), func() (net.Conn, error) {
			if fail {
				return raw, errors.New("failed")
			}
			_ = raw.Close()
			return nil, nil
		})
		if err == nil {
			t.Fatal("bad dial result accepted")
		}
		if _, err := peer.Write([]byte{1}); err == nil {
			t.Fatal("failed dial leaked connection")
		}
		_ = peer.Close()
	}
}
