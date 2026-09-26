// Package embed is the "embedded Tor client": it bootstraps a gonion
// connection, maintains a pool of exit circuits, and exposes a net.Dialer that
// builds circuits on demand — including .onion hidden services via pkg/hs.
package embed

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	gonion "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
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

	mu        sync.RWMutex
	circuits  []*pooledCircuit
	nextID    atomic.Uint32
	lifetime  context.Context
	cancel    context.CancelFunc
	listeners map[*Listener]struct{}

	hs *hs.Client

	longLived bool
	closed    bool
	ttl       time.Duration
	maxUses   int64
}

// Options configures a Client.
type Options struct {
	Storage storage.Storage
	// ORDialer opens only the bootstrap connection. It must honor ctx.
	ORDialer func(ctx context.Context) (net.Conn, error)
	// BootstrapIdentity is the expected RSA fingerprint of the bootstrap relay.
	// Required unless the connection provides ExpectedRelayIdentity() [20]byte
	// (as the built-in fallback dialer does). A raw TLS certificate is not a pin.
	BootstrapIdentity [20]byte
	// GuardDialer opens the selected guard for every traffic circuit, including
	// onion circuits. It must honor ctx and must not substitute a different relay.
	// Nil disables traffic circuit construction; there is no direct TCP fallback.
	// A fixed bridge needs bridge-aware path selection, not this callback.
	GuardDialer func(ctx context.Context, guard *common.RouterStatus) (net.Conn, error)
	LongLived   bool
	// Zero selects the defaults. Negative values are invalid.
	CircuitTTL     time.Duration
	MaxCircuitUses int64
}

// DefaultOptions returns the local pool defaults plus two direct TCP dialers:
// a fallback directory connection for bootstrap and a connection to the selected
// traffic guard. Both are ordinary visible options, so a caller that needs a
// different policy replaces or clears them; a cleared dialer fails closed
// instead of falling back to direct TCP. Storage stays caller-owned and embed
// never closes it.
func DefaultOptions() Options {
	return Options{
		CircuitTTL:     circuitTTL,
		MaxCircuitUses: maxCircuitUses,
		ORDialer:       defaultORDialer,
		GuardDialer:    defaultGuardDialer,
	}
}

func defaultORDialer(ctx context.Context) (net.Conn, error) {
	return fallback.New(shared.Fallbacks).DialContext(ctx, true)
}

func defaultGuardDialer(ctx context.Context, guard *common.RouterStatus) (net.Conn, error) {
	return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(guard.Ipv4Addr, strconv.Itoa(int(guard.ORPort))))
}

func (o Options) validate() error {
	if o.CircuitTTL < 0 || o.MaxCircuitUses < 0 {
		return fmt.Errorf("embed: negative circuit pool limit")
	}
	return nil
}

// New bootstraps a fresh embedded client: it dials a guard/fallback, performs
// the link handshake, bootstraps consensus+microdescriptors, and is ready to
// dial immediately.
func New(ctx context.Context, opts Options) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if opts.ORDialer == nil {
		return nil, fmt.Errorf("embed: ORDialer is required for New")
	}
	orConn, err := opts.ORDialer(ctx)
	if err != nil {
		if orConn != nil {
			_ = orConn.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return NewWithConn(ctx, orConn, opts)
}

// NewWithConn wraps an already-established OR connection (e.g. over a pluggable
// transport) and bootstraps on top of it.
func NewWithConn(ctx context.Context, orConn net.Conn, opts Options) (*Client, error) {
	if orConn == nil {
		return nil, fmt.Errorf("embed: nil OR connection")
	}
	if err := opts.validate(); err != nil {
		_ = orConn.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = orConn.Close()
		return nil, err
	}
	identity := opts.BootstrapIdentity
	if pinned, ok := orConn.(interface{ ExpectedRelayIdentity() [20]byte }); ok {
		if identity != [20]byte{} && identity != pinned.ExpectedRelayIdentity() {
			_ = orConn.Close()
			return nil, fmt.Errorf("embed: conflicting bootstrap identity pins")
		}
		identity = pinned.ExpectedRelayIdentity()
	}
	if identity == [20]byte{} {
		_ = orConn.Close()
		return nil, fmt.Errorf("embed: bootstrap relay identity is required")
	}
	stop := context.AfterFunc(ctx, func() { _ = orConn.Close() })
	defer stop()
	conn, err := gonion.NewConn(orConn, nil, false)
	if err != nil {
		_ = orConn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := conn.CheckRelayFingerprint(identity); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stopBootstrap := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopBootstrap()
	if opts.Storage != nil {
		conn.SetStorage(opts.Storage)
	}
	if err := gonion.BootstrapOneConn(conn); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}

	cns := conn.Consensus()
	if !cns.IsAuthenticated() {
		_ = conn.Close()
		return nil, fmt.Errorf("embed: no consensus after bootstrap")
	}

	c := &Client{
		conn:      conn,
		storage:   opts.Storage,
		cns:       cns,
		hs:        &hs.Client{},
		longLived: opts.LongLived,
		builder:   gonionBuilder{dial: opts.GuardDialer},
		ttl:       opts.CircuitTTL,
		maxUses:   opts.MaxCircuitUses,
	}
	if !stopBootstrap() || !stop() || ctx.Err() != nil {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	go c.reapLoop(conn.Context())
	return c, nil
}

// Conn exposes the underlying gonion connection (for advanced use).
func (c *Client) Conn() *gonion.Conn { return c.conn }

// Consensus returns the current bootstrapped consensus.
func (c *Client) Consensus() *common.Consensus {
	if c.conn != nil {
		return c.conn.Consensus()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cns.Clone()
}

// Close stops pending operations, listeners, and all traffic circuits, including
// accepted onion streams whose listener has already been closed.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	circuits := c.circuits
	c.circuits = nil
	listeners := c.listeners
	c.listeners = nil
	c.mu.Unlock()
	for l := range listeners {
		_ = l.Shutdown()
	}
	for _, pc := range circuits {
		_ = pc.circ.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// pooledCircuit wraps a circuit with pool bookkeeping.
type pooledCircuit struct {
	circ      capi.Circ
	createdAt time.Time
	expiresAt time.Time
	uses      atomic.Int64
	invalid   atomic.Bool
	active    bool // protected by Client.mu; includes a pending stream open
	port      uint16
}

const (
	// circuitTTL is how long a pooled exit circuit is kept before rotation.
	circuitTTL = 10 * time.Minute
	// maxCircuitUses caps a circuit's stream count before rotation.
	maxCircuitUses = 100
)
