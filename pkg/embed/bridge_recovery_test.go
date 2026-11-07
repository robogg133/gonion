package embed

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
)

type wrongBridgePin struct {
	net.Conn
	identity [20]byte
}

func (c wrongBridgePin) ExpectedRelayIdentity() [20]byte { return c.identity }

func TestBridgeRetryBeforeRetainedKeyExpires(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	d := &common.BridgeDescriptor{Relay: cns.RelayInformation[0], Expires: time.Now().Add(20 * time.Minute)}
	b := &bridgeState{identity: d.Relay.NodeID, lock: make(chan struct{}, 1), descriptor: d, fetch: func(context.Context) (*common.BridgeDescriptor, error) { return nil, errors.New("temporary outage") }}
	if _, err := b.guard(context.Background()); err != nil {
		t.Fatal("discarded still-valid signed descriptor:", err)
	}
	if !b.nextFetch.Before(d.Expires) {
		t.Fatal("retry scheduled after descriptor expiry")
	}
}

func TestBridgeRecoveryFailClosed(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	d := &common.BridgeDescriptor{Relay: cns.RelayInformation[0], Expires: time.Now().Add(-time.Second)}
	calls := 0
	bridge := BridgeOptions{Identity: d.Relay.NodeID, DialContext: func(context.Context) (net.Conn, error) { calls++; return nil, errors.New("dialed") }}
	if _, err := fetchBridgeDescriptor(context.Background(), bridge, d); err == nil || calls != 0 {
		t.Fatal("expired key authorized redial")
	}
	d.Expires = time.Now().Add(time.Hour)
	raw, peer := net.Pipe()
	defer peer.Close()
	bridge.DialContext = func(context.Context) (net.Conn, error) {
		calls++
		return wrongBridgePin{Conn: raw, identity: [20]byte{99}}, nil
	}
	if _, err := fetchBridgeDescriptor(context.Background(), bridge, d); err == nil || calls != 1 {
		t.Fatal("mismatched pinned bridge accepted")
	}
	if _, err := peer.Write([]byte{1}); err == nil {
		t.Fatal("rejected bridge connection leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bridge.DialContext = func(context.Context) (net.Conn, error) { calls++; return nil, context.Canceled }
	if _, err := fetchBridgeDescriptor(ctx, bridge, d); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}
