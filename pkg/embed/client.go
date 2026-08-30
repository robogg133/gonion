// Package embed is the "embedded Tor client": it bootstraps a gonion
// connection, maintains a pool of exit circuits, and exposes a net.Dialer that
// builds circuits on demand — including .onion hidden services via pkg/hs.
package embed

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	gonion "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/storage"
)

// Client is an embedded Tor-like client. It is safe for concurrent use.
type Client struct {
	conn    *gonion.Conn
	storage storage.Storage
	cns     *common.Consensus

	// builder constructs circuits. Set by New/NewWithConn; overridable in
	// tests with a stub.
	builder capi.CircuitBuilder

	mu       sync.RWMutex
	circuits []*pooledCircuit
	nextID   atomic.Uint32

	hs *hs.Client

	longLived bool
}

// Options configures a Client.
type Options struct {
	Storage storage.Storage
	// ORDialer opens the first OR connection (to a guard / fallback dir). When
	// nil, the caller must provide an already-connected *gonion.Conn via
	// NewWithConn.
	ORDialer  func(ctx context.Context) (net.Conn, error)
	LongLived bool
}

// New bootstraps a fresh embedded client: it dials a guard/fallback, performs
// the link handshake, bootstraps consensus+microdescriptors, and is ready to
// dial immediately.
func New(ctx context.Context, opts Options) (*Client, error) {
	if opts.ORDialer == nil {
		return nil, fmt.Errorf("embed: ORDialer is required for New")
	}
	orConn, err := opts.ORDialer(ctx)
	if err != nil {
		return nil, err
	}
	return NewWithConn(ctx, orConn, opts)
}

// NewWithConn wraps an already-established OR connection (e.g. over a pluggable
// transport) and bootstraps on top of it.
func NewWithConn(ctx context.Context, orConn net.Conn, opts Options) (*Client, error) {
	conn, err := gonion.NewConn(orConn, nil, false)
	if err != nil {
		return nil, err
	}
	if opts.Storage != nil {
		conn.SetStorage(opts.Storage)
	}
	if err := gonion.BootstrapOneConn(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	cns := common.GetGlobalConsensus()
	if cns == nil {
		if opts.Storage != nil {
			cns, _ = opts.Storage.GetConsensus()
		}
	}
	if cns == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("embed: no consensus after bootstrap")
	}

	c := &Client{
		conn:      conn,
		storage:   opts.Storage,
		cns:       cns,
		hs:        &hs.Client{},
		longLived: opts.LongLived,
		builder:   gonionBuilder{},
	}
	go c.reapLoop(ctx)
	return c, nil
}

// Conn exposes the underlying gonion connection (for advanced use).
func (c *Client) Conn() *gonion.Conn { return c.conn }

// Consensus returns the current bootstrapped consensus.
func (c *Client) Consensus() *common.Consensus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cns
}

// Close shuts the client and all pooled circuits down.
func (c *Client) Close() error {
	c.mu.Lock()
	for _, pc := range c.circuits {
		_ = pc.circ.Close()
	}
	c.circuits = nil
	c.mu.Unlock()
	return c.conn.Close()
}

// pooledCircuit wraps a circuit with pool bookkeeping.
type pooledCircuit struct {
	circ      capi.Circ
	createdAt time.Time
	expiresAt time.Time
	uses      atomic.Int64
	invalid   atomic.Bool
}

const (
	// circuitTTL is how long a pooled exit circuit is kept before rotation.
	circuitTTL = 10 * time.Minute
	// maxCircuitUses caps a circuit's stream count before rotation.
	maxCircuitUses = 100
)
