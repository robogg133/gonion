package embed

import (
	"context"
	"fmt"
	"net"
	"time"

	gonion "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/common"
)

// BridgeOptions selects one bridge for bootstrap and EVERY traffic purpose.
// Identity is the Tor RSA fingerprint, not a transport certificate/key. The
// caller chooses and retains this identity across restarts. DialContext must
// open that bridge's byte stream, honor ctx, and be safe for concurrent calls.
// This is not Tor's persistent multi-bridge guard-selection algorithm.
type BridgeOptions struct {
	Identity    [20]byte
	DialContext func(context.Context) (net.Conn, error)
}

// DefaultBridgeOptions keeps the ordinary pool limits but removes both direct
// dialers. A missing/failed bridge configuration always fails closed.
func DefaultBridgeOptions(bridge BridgeOptions) Options {
	opts := DefaultOptions()
	opts.ORDialer, opts.GuardDialer = nil, nil
	opts.Bridge = &bridge
	return opts
}

type bridgeState struct {
	identity   [20]byte
	lock       chan struct{}
	descriptor *common.BridgeDescriptor
	nextFetch  time.Time
	fetch      func(context.Context) (*common.BridgeDescriptor, error)
	lastErr    error
}

func newBridgeState(ctx context.Context, conn *gonion.Conn, identity [20]byte) (*bridgeState, error) {
	// CREATE_FAST is needed only to learn the initially unknown ntor key over
	// pinned TLS. This one-hop circuit is never extended or used for traffic.
	directory, err := conn.NewFastCircuit(2)
	if err != nil {
		return nil, err
	}
	b := &bridgeState{identity: identity, lock: make(chan struct{}, 1)}
	b.fetch = func(ctx context.Context) (*common.BridgeDescriptor, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { _ = directory.Close() })
		defer stop()
		d, err := directory.GetBridgeDescriptor(ctx, identity)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return d, err
	}
	if _, err := b.guard(ctx); err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("embed: bridge descriptor: %w", err)
	}
	return b, nil
}

func (b *bridgeState) guard(ctx context.Context) (*common.RouterStatus, error) {
	select {
	case b.lock <- struct{}{}:
		defer func() { <-b.lock }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	if !now.Before(b.nextFetch) {
		d, err := b.fetch(ctx)
		if err == nil && (d == nil || d.Relay.NodeID != b.identity || !now.Before(d.Expires)) {
			err = fmt.Errorf("embed: invalid refreshed bridge descriptor")
		}
		if err == nil && b.descriptor != nil && d.Published.Before(b.descriptor.Published) {
			err = fmt.Errorf("embed: bridge descriptor publication went backwards")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// ponytail: one configured bridge, fixed three-hour refresh/retry cadence
		// (dir-spec 5.5 base delay); full guard reachability/backoff is separate.
		b.nextFetch = now.Add(3 * time.Hour)
		b.lastErr = err
		if err == nil {
			b.descriptor = d
			if d.Expires.Before(b.nextFetch) {
				b.nextFetch = d.Expires
			}
		}
	}
	if b.descriptor == nil || !time.Now().Before(b.descriptor.Expires) {
		if b.lastErr != nil {
			return nil, b.lastErr
		}
		return nil, fmt.Errorf("embed: bridge descriptor expired")
	}
	// Isolate the authenticated snapshot from selectors and caller dialers.
	copy := (&common.Consensus{RelayInformation: []common.RouterStatus{b.descriptor.Relay}}).Clone()
	return &copy.RelayInformation[0], nil
}
