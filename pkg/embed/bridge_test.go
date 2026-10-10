package embed

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

func TestBridgeOptionsFailClosed(t *testing.T) {
	want := errors.New("bridge unavailable")
	bridgeCalls, directCalls := 0, 0
	bridge := BridgeOptions{Identity: [20]byte{1}, DialContext: func(context.Context) (net.Conn, error) { bridgeCalls++; return nil, want }}
	opts := DefaultBridgeOptions(bridge)
	if opts.ORDialer != nil || opts.GuardDialer != nil || opts.Storage != nil || opts.CircuitTTL != 10*time.Minute {
		t.Fatal("unsafe bridge defaults")
	}
	// Even inherited/reinstalled direct defaults are unreachable in bridge mode.
	opts.ORDialer = func(context.Context) (net.Conn, error) { directCalls++; return nil, errors.New("direct") }
	opts.GuardDialer = func(context.Context, *common.RouterStatus) (net.Conn, error) {
		directCalls++
		return nil, errors.New("direct")
	}
	if _, err := New(context.Background(), opts); !errors.Is(err, want) || bridgeCalls != 1 || directCalls != 0 {
		t.Fatalf("bridge fallback: %v", err)
	}
	for _, modify := range []func(*Options){
		func(o *Options) { o.Bridge.Identity = [20]byte{} },
		func(o *Options) { o.Bridge.DialContext = nil },
		func(o *Options) { o.BootstrapIdentity = [20]byte{2} },
		func(o *Options) { o.IgnoreRelayCheck = true },
		func(o *Options) { o.ORConnectionSkipRelayFingerprintCheck = true },
		func(o *Options) { o.GuardConnectionSkipRelayFingerprintCheck = true },
	} {
		o := DefaultBridgeOptions(bridge)
		modify(&o)
		if _, err := New(context.Background(), o); err == nil || bridgeCalls != 1 {
			t.Fatal("invalid bridge configuration performed I/O")
		}
	}
	b := gonionBuilder{bridge: &bridgeState{identity: bridge.Identity}, dial: opts.GuardDialer}
	if _, err := b.BuildPath(1, []*common.RouterStatus{{NodeID: [20]byte{2}}}); err == nil || directCalls != 0 {
		t.Fatal("mismatched selected guard dialed")
	}
}

func TestBridgeBootstrapIdentityAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		raw, peer := net.Pipe()
		opts := DefaultBridgeOptions(BridgeOptions{Identity: [20]byte{1}, DialContext: func(context.Context) (net.Conn, error) { return nil, nil }})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		if canceled {
			cancel()
		}
		_, err := NewWithConn(ctx, raw, opts)
		cancel()
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("bridge handshake: %v", err)
		}
		if _, err := peer.Write([]byte{1}); err == nil {
			t.Fatal("canceled bridge leaked")
		}
		_ = peer.Close()
	}
}

func TestBridgeDescriptorRefresh(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	d := &common.BridgeDescriptor{Relay: cns.RelayInformation[0], Published: time.Now().Add(-time.Hour), Expires: time.Now().Add(time.Hour)}
	var calls atomic.Int32
	b := &bridgeState{identity: d.Relay.NodeID, lock: make(chan struct{}, 1), fetch: func(context.Context) (*common.BridgeDescriptor, error) { calls.Add(1); return d, nil }}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, err := b.guard(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			r.IdEd25519[0] ^= 255 // The retained authenticated snapshot is private.
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate refreshes: %d", calls.Load())
	}
	if b.descriptor.Relay.IdEd25519[0] != cns.RelayInformation[0].IdEd25519[0] {
		t.Fatal("snapshot mutated")
	}
	b.lock <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.guard(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("refresh lock ignored cancellation")
	}
	<-b.lock
	b.nextFetch = time.Time{}
	want := errors.New("directory lost")
	b.fetch = func(context.Context) (*common.BridgeDescriptor, error) { return nil, want }
	if _, err := b.guard(context.Background()); err != nil {
		t.Fatalf("discarded still-valid descriptor: %v", err)
	}
	b.descriptor.Expires = time.Now().Add(-time.Second)
	if _, err := b.guard(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expired descriptor accepted: %v", err)
	}
	b.nextFetch = time.Time{}
	b.fetch = func(context.Context) (*common.BridgeDescriptor, error) {
		copy := *d
		copy.Relay.NodeID = [20]byte{99}
		return &copy, nil
	}
	if _, err := b.guard(context.Background()); err == nil {
		t.Fatal("refreshed bridge identity changed")
	}
}

type fixedGuardBuilder struct {
	*stubBuilder
	guard *common.RouterStatus
}

func (b fixedGuardBuilder) CircuitGuard(context.Context) (*common.RouterStatus, error) {
	return b.guard, nil
}
func (b fixedGuardBuilder) BuildPath(id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	if relays[0].NodeID != b.guard.NodeID {
		return nil, errors.New("selected a public guard")
	}
	return b.stubBuilder.BuildPath(id, relays)
}

func TestExitAndContextBuilderKeepBridge(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	guard := cns.RelayInformation[0]
	guard.NodeID, guard.Ipv4Addr = [20]byte{99}, "192.0.2.1"
	b := fixedGuardBuilder{stubBuilder: &stubBuilder{}, guard: &guard}
	c := newTestClient(t, b)
	conn, err := c.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	wrapped := contextBuilder{ctx: context.Background(), builder: b}
	got, err := capi.CircuitGuard(context.Background(), wrapped)
	if err != nil || got.NodeID != guard.NodeID {
		t.Fatalf("onion builder lost bridge: %v", err)
	}
}
