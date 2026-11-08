// Package embed is the "embedded Tor client": it bootstraps a gonion
// connection, maintains a pool of exit circuits, and exposes a net.Dialer that
// builds circuits on demand — including .onion hidden services via pkg/hs.
package embed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gonion "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/path"
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

	// Observability (E4.3). obs is nil unless Options.Log was supplied;
	// guardMode, bootstrappedAt and bridge describe the caller-selected
	// networking policy for Stats snapshots. None of these carry user
	// destination data.
	obs            *observability
	guardMode      string
	bootstrappedAt time.Time
	bridge         *bridgeState

	longLived bool
	closed    bool
	ttl       time.Duration
	maxUses   int64
}

// Options configures a Client.
type Options struct {
	Storage storage.Storage
	// Guards is a caller-created persistent public-default manager, shared by
	// all public traffic purposes. Required outside pinned bridge mode.
	// Construct it with path.NewGuardManager and caller-owned durable callbacks.
	Guards *path.GuardManager
	// Bridge, when non-nil, overrides BOTH dialers with a pinned fixed bridge.
	// There is no public-relay fallback, even when using DefaultOptions.
	Bridge *BridgeOptions
	// ORDialer opens only the bootstrap connection. It must honor ctx.
	ORDialer func(ctx context.Context) (net.Conn, error)
	// BootstrapIdentity is the expected RSA fingerprint of the bootstrap relay.
	// Required unless the connection provides ExpectedRelayIdentity() [20]byte
	// (as the built-in fallback dialer does). A raw TLS certificate is not a pin.
	BootstrapIdentity [20]byte
	// Authorities replaces the default nine public C Tor authority pins with an
	// explicit caller-supplied set (private or controlled networks). Validation
	// rules live on gonion.Conn.SetTrustedAuthorities; the set is used for a
	// strict majority quorum and does not relax relay/bridge identity checks.
	Authorities [][20]byte
	// GuardDialer opens the selected guard for every traffic circuit, including
	// onion circuits. It must honor ctx and must not substitute a different relay.
	// Nil disables traffic circuit construction; there is no direct TCP fallback.
	// To use a fixed bridge, set Bridge rather than substituting this callback.
	GuardDialer func(ctx context.Context, guard *common.RouterStatus) (net.Conn, error)
	LongLived   bool
	// Zero selects the defaults. Negative values are invalid.
	CircuitTTL     time.Duration
	MaxCircuitUses int64
	// Log, when non-nil, receives privacy-safe operational messages through
	// the standard library log package: bootstrap start/ready, circuit build
	// and guard dial failures, bridge descriptor refresh failures, and
	// listener registration. Messages never contain stream destinations,
	// onion addresses, rendezvous cookies, key material, or descriptor
	// plaintext. Relay fingerprints and connection endpoints may appear
	// because they identify the operator's own links, not user traffic.
	// The default nil keeps the client completely silent. Stats is the
	// structured snapshot; no metrics dependency is introduced.
	//
	// Security-required migration (E4.1): the former skip-relay-check option
	// fields and the legacy skip-check context key are removed, not rejected
	// at runtime. Assigning to them is now a compile error. Every bootstrap
	// and traffic channel always verifies CERTS-derived relay identity
	// against an explicit pin; no direct or bridge configuration can decline
	// the check. Callers previously setting those fields must delete the
	// assignment and supply BootstrapIdentity (or a connection carrying
	// ExpectedRelayIdentity). Setting a raw TLS InsecureSkipVerify-style
	// option is never a substitute.
	Log io.Writer
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
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(guard.Ipv4Addr, strconv.Itoa(int(guard.ORPort))))
	if ctx.Err() == nil && (errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ETIMEDOUT)) {
		err = &capi.GuardConnectionFailure{Err: err}
	}
	return conn, err
}

func (o Options) validate() error {
	if o.Bridge == nil && o.Guards == nil {
		return path.ErrGuardPersistence
	}
	if o.CircuitTTL < 0 || o.MaxCircuitUses < 0 {
		return fmt.Errorf("embed: negative circuit pool limit")
	}
	if o.Bridge != nil {
		if o.Bridge.Identity == [20]byte{} || o.Bridge.DialContext == nil {
			return fmt.Errorf("embed: bridge identity and DialContext are required")
		}
		if o.BootstrapIdentity != [20]byte{} && o.BootstrapIdentity != o.Bridge.Identity {
			return fmt.Errorf("embed: conflicting bridge and bootstrap identity pins")
		}
		// There is nothing left to forbid: the former skip-check fields no
		// longer exist and bridge identity is always enforced below.
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
	dial := opts.ORDialer
	if opts.Bridge != nil {
		dial = opts.Bridge.DialContext
	}
	if dial == nil {
		return nil, fmt.Errorf("embed: ORDialer is required for New")
	}
	obs := newObservability(opts.Log)
	obs.logf("bootstrap: dialing")
	orConn, err := dial(ctx)
	if err != nil {
		if orConn != nil {
			_ = orConn.Close()
		}
		obs.logf("bootstrap: dial failed: %v", err)
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
	if opts.Bridge != nil {
		identity = opts.Bridge.Identity
	}
	if pinned, ok := orConn.(interface{ ExpectedRelayIdentity() [20]byte }); ok {
		if identity != [20]byte{} && identity != pinned.ExpectedRelayIdentity() {
			_ = orConn.Close()
			return nil, fmt.Errorf("embed: conflicting bootstrap identity pins")
		}
		identity = pinned.ExpectedRelayIdentity()
	}

	// There is no configuration that declines this requirement: the former
	// skip-check fields are removed (security-required migration, E4.1).
	if identity == [20]byte{} {
		_ = orConn.Close()
		return nil, fmt.Errorf("embed: bootstrap relay identity is required")
	}

	obs := newObservability(opts.Log)
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
	if opts.Authorities != nil {
		if err := conn.SetTrustedAuthorities(opts.Authorities); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	builder := gonionBuilder{dial: opts.GuardDialer, guards: opts.Guards, obs: obs}
	recoveryDial := opts.ORDialer
	if opts.Bridge == nil && recoveryDial != nil {
		// A built-in fallback connection carries the *selected endpoint's*
		// explicit redial policy. An arbitrary ORDialer is never replaced
		// unless it deliberately returned that pinned capability.
		if pinned, ok := orConn.(interface {
			RedialExpectedRelay(context.Context, [20]byte) (net.Conn, error)
		}); ok {
			recoveryDial = func(ctx context.Context) (net.Conn, error) {
				return pinned.RedialExpectedRelay(ctx, identity)
			}
		}
	}
	if opts.Bridge != nil {
		bridge := *opts.Bridge // Do not retain caller-mutable configuration.
		recoveryDial = bridge.DialContext
		builder.bridge, err = newBridgeState(ctx, conn, bridge, obs)
		if err == nil {
			builder.dial = func(ctx context.Context, _ *common.RouterStatus) (net.Conn, error) {
				return bridge.DialContext(ctx)
			}
			err = gonion.BootstrapOneConnManaged(conn, &builder.bridge.descriptor.Relay)
		}
	} else {
		err = gonion.BootstrapOneConnManaged(conn, nil)
	}
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}

	cns := conn.Consensus()
	if !cns.IsAuthenticated() || !cns.TrustedHydrated() {
		_ = conn.Close()
		return nil, fmt.Errorf("embed: no consensus after bootstrap")
	}

	c := &Client{
		conn:           conn,
		storage:        opts.Storage,
		cns:            cns,
		hs:             &hs.Client{},
		longLived:      opts.LongLived,
		builder:        builder,
		ttl:            opts.CircuitTTL,
		maxUses:        opts.MaxCircuitUses,
		obs:            obs,
		bootstrappedAt: time.Now().UTC(),
		bridge:         builder.bridge,
	}
	if builder.bridge != nil {
		c.guardMode = "pinned-bridge"
	} else {
		c.guardMode = "public-guard"
	}
	obs.logf("bootstrap: ready relays=%d mode=%s", len(cns.RelayInformation), c.guardMode)
	if !stopBootstrap() || !stop() || ctx.Err() != nil {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	c.lifetime, c.cancel = context.WithCancel(context.Background())
	var guard func(context.Context) (*common.RouterStatus, error)
	if builder.bridge != nil {
		guard = builder.bridge.guard
	}
	if err := conn.StartConsensusRecovery(recoveryDial, identity, guard); err != nil {
		c.cancel()
		_ = conn.Close()
		return nil, err
	}
	go c.reapLoop(c.lifetime)
	return c, nil
}

// Conn exposes the initial bootstrap channel (for advanced use). Directory
// recovery may move to a different channel; use Client.Consensus for snapshots.
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

// Stats is a privacy-safe operational snapshot using only standard-library
// types (E4.3). It is a moment-in-time copy; no live objects or high-
// cardinality destination labels are retained. Counts are what this Client
// instance observed since construction; they never contain stream
// destinations, onion addresses, cookies, keys, or descriptor plaintext.
type Stats struct {
	// Bootstrap and directory health.
	BootstrappedAt           time.Time
	BootstrapAge             time.Duration
	ConsensusPresent         bool
	ConsensusAuthenticated   bool
	ConsensusTrustedHydrated bool
	ConsensusLive            bool
	ConsensusAge             time.Duration
	ConsensusRelays          int

	// Traffic circuit construction as observed by the pool and dialer.
	CircuitsBuilt        uint64
	CircuitBuildFailures uint64
	GuardDialFailures    uint64
	IdentityMismatches   uint64
	ActiveCircuits       int

	// Guard policy state. GuardMode is "pinned-bridge" or "public-guard";
	// Bridge fields only apply in pinned-bridge mode.
	GuardMode             string
	BridgeDescriptorValid bool
	BridgeNextFetch       time.Time
	BridgeRefreshFailures uint64

	// Onion service listener maintenance. ListenerFaults counts listeners
	// whose Err() is currently non-nil; successful renewal clears that
	// error in the underlying listener.
	Listeners      int
	ListenerFaults int

	Closed bool
}

// Stats returns the current operational snapshot. It is safe at any time,
// including before bootstrap or after Close, and performs no networking.
// Operators can distinguish failure classes without library changes:
// directory/recovery problems show as ConsensusLive=false with growing
// ConsensusAge; guard problems as rising GuardDialFailures or an invalid
// bridge snapshot; circuit problems as CircuitBuildFailures with the
// bootstrap fields still healthy; service problems as ListenerFaults > 0.
func (c *Client) Stats() Stats {
	var s Stats
	if cns := c.Consensus(); cns != nil {
		s.ConsensusPresent = true
		s.ConsensusAuthenticated = cns.IsAuthenticated()
		s.ConsensusTrustedHydrated = cns.TrustedHydrated()
		s.ConsensusLive = cns.IsLive(time.Now())
		s.ConsensusRelays = len(cns.RelayInformation)
		if age := time.Since(cns.ValidAfter.UTC()); age > 0 {
			s.ConsensusAge = age
		}
	}
	c.mu.RLock()
	s.ActiveCircuits = len(c.circuits)
	s.Listeners = len(c.listeners)
	s.Closed = c.closed
	for l := range c.listeners {
		if l.Err() != nil {
			s.ListenerFaults++
		}
	}
	s.GuardMode = c.guardMode
	obs, bridge := c.obs, c.bridge
	bootstrapped := c.bootstrappedAt
	c.mu.RUnlock()
	if obs != nil {
		s.CircuitsBuilt = obs.built.Load()
		s.CircuitBuildFailures = obs.buildFailures.Load()
		s.GuardDialFailures = obs.guardDialFailures.Load()
		s.IdentityMismatches = obs.identityMismatches.Load()
		s.BridgeRefreshFailures = obs.bridgeRefreshFailures.Load()
	}
	if bridge != nil {
		s.BridgeDescriptorValid, s.BridgeNextFetch = bridge.snapshot()
	}
	if !bootstrapped.IsZero() {
		s.BootstrappedAt = bootstrapped
		s.BootstrapAge = time.Since(bootstrapped)
	}
	return s
}

// observability is the single private holder for the optional log writer and
// the standard-library counters behind Stats. A nil *observability is valid
// and completely silent, so the default path allocates nothing and writes
// nothing.
type observability struct {
	log                   *log.Logger // nil means silent
	built                 atomic.Uint64
	buildFailures         atomic.Uint64
	guardDialFailures     atomic.Uint64
	identityMismatches    atomic.Uint64
	bridgeRefreshFailures atomic.Uint64
}

func newObservability(w io.Writer) *observability {
	o := &observability{}
	if w != nil {
		o.log = log.New(w, "gonion embed: ", log.LstdFlags)
	}
	return o
}

func (o *observability) logf(format string, args ...any) {
	if o == nil || o.log == nil {
		return
	}
	o.log.Output(2, fmt.Sprintf(format, args...))
}

// Named counters are nil-safe so the default silent path needs no
// observability object at all.
func (o *observability) countBuilt() {
	if o != nil {
		o.built.Add(1)
	}
}
func (o *observability) countBuildFailure() {
	if o != nil {
		o.buildFailures.Add(1)
	}
}
func (o *observability) countGuardDialFailure() {
	if o != nil {
		o.guardDialFailures.Add(1)
	}
}
func (o *observability) countIdentityMismatch() {
	if o != nil {
		o.identityMismatches.Add(1)
	}
}
func (o *observability) countBridgeRefreshFailure() {
	if o != nil {
		o.bridgeRefreshFailures.Add(1)
	}
}
