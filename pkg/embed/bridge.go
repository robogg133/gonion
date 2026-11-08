package embed

import (
	"context"
	"fmt"
	"net"
	"sync"
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
	obs        *observability

	// snapshotMu guards the Stats-visible fields only; the refresh schedule
	// itself stays under the lock channel.
	snapshotMu        sync.Mutex
	observedValid     bool
	observedNextFetch time.Time
}

func newBridgeState(ctx context.Context, conn *gonion.Conn, bridge BridgeOptions, obs *observability) (*bridgeState, error) {
	identity := bridge.Identity
	// CREATE_FAST is needed only to learn the initially unknown ntor key over
	// pinned TLS. This one-hop circuit is never extended or used for traffic.
	directory, err := conn.NewFastCircuit(2)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	b := &bridgeState{identity: identity, lock: make(chan struct{}, 1), obs: obs}
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
		return nil, fmt.Errorf("embed: bridge descriptor: %w", err)
	}
	// Never reuse the initial CREATE_FAST circuit. Once a verified descriptor
	// supplies ntor, every refresh uses a newly authenticated pinned channel.
	b.fetch = func(ctx context.Context) (*common.BridgeDescriptor, error) {
		return fetchBridgeDescriptor(ctx, bridge, b.descriptor)
	}
	return b, nil
}

// Called with bridgeState.lock held; the signed descriptor supplies the ntor
// key and Ed identity. An expired key cannot authorize a new circuit.
func fetchBridgeDescriptor(ctx context.Context, bridge BridgeOptions, previous *common.BridgeDescriptor) (*common.BridgeDescriptor, error) {
	if previous == nil || !time.Now().Before(previous.Expires) {
		return nil, fmt.Errorf("embed: bridge descriptor key expired; ntor recovery unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	raw, err := bridge.DialContext(ctx)
	if err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("embed: bridge dialer returned nil connection")
	}
	if pinned, ok := raw.(interface{ ExpectedRelayIdentity() [20]byte }); ok && pinned.ExpectedRelayIdentity() != bridge.Identity {
		_ = raw.Close()
		return nil, fmt.Errorf("embed: bridge dialer identity pin changed")
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop() // Also interrupt a blocked ntor circuit or descriptor fetch.
	link, err := gonion.NewConn(raw, nil, false)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	defer link.Close()
	if err := link.CheckRelayIdentity(&previous.Relay); err != nil {
		return nil, err
	}
	circuit, err := link.NewCircuitTo(2, &previous.Relay)
	if err != nil {
		return nil, err
	}
	defer circuit.Close()
	descriptor, err := circuit.GetBridgeDescriptor(ctx, bridge.Identity)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return descriptor, err
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
		// Retry failures while the retained ntor key is still valid; never
		// wait for its expiry before the next attempt.
		b.nextFetch = now.Add(3 * time.Hour)
		if err != nil {
			b.nextFetch = now.Add(30 * time.Minute)
			if b.descriptor != nil && b.descriptor.Expires.Before(b.nextFetch) {
				b.nextFetch = now.Add(b.descriptor.Expires.Sub(now) / 2)
			}
		}
		b.lastErr = err
		if err != nil {
			b.obs.countBridgeRefreshFailure()
			b.obs.logf("bridge: descriptor refresh failed: %v", err)
		} else {
			b.descriptor = d
			b.obs.logf("bridge: descriptor refreshed")
			if until := d.Expires.Sub(now) / 2; until < b.nextFetch.Sub(now) {
				b.nextFetch = now.Add(until)
			}
		}
	}
	if b.descriptor == nil || !time.Now().Before(b.descriptor.Expires) {
		b.observe()
		if b.lastErr != nil {
			return nil, b.lastErr
		}
		return nil, fmt.Errorf("embed: bridge descriptor expired")
	}
	// Isolate the authenticated snapshot from selectors and caller dialers.
	copy := (&common.Consensus{RelayInformation: []common.RouterStatus{b.descriptor.Relay}}).Clone()
	b.observe()
	return &copy.RelayInformation[0], nil
}

// observe publishes the current retention state for Stats. Called with the
// refresh lock held.
func (b *bridgeState) observe() {
	valid := b.descriptor != nil && time.Now().Before(b.descriptor.Expires)
	b.snapshotMu.Lock()
	b.observedValid = valid
	b.observedNextFetch = b.nextFetch
	b.snapshotMu.Unlock()
}

// snapshot is the privacy-safe guard-state view for Stats: validity and the
// next scheduled refresh only, never key material or descriptor plaintext.
func (b *bridgeState) snapshot() (valid bool, nextFetch time.Time) {
	b.snapshotMu.Lock()
	defer b.snapshotMu.Unlock()
	return b.observedValid, b.observedNextFetch
}
