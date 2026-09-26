package embed

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	"sync"
	"time"

	"github.com/robogg133/gonion/pkg/hs"

	gonion "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/onion"
	"github.com/robogg133/gonion/pkg/path"
)

// DialContext implements net.Dialer's DialContext: it builds (or reuses) a
// circuit for addr and returns a net.Conn tunneled through it. .onion addresses
// are routed through the hidden-service rendezvous. The client fully owns the
// circuit lifecycle: it creates circuits on demand, reuses healthy ones from
// the pool, and retries on a fresh circuit when a stream/circuit fails.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, finish, err := c.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	// The current stream API cannot express IPv6 BEGIN flags.
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("embed: unsupported network %q", network)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" || portOf(addr) == 0 || strings.ContainsAny(host, "\x00\r\n\t /%") || len(host) > 253 {
		return nil, fmt.Errorf("embed: invalid TCP address %q", addr)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return nil, fmt.Errorf("embed: IPv6 streams are not supported")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || strings.ContainsAny(host, ":[]\\") || strings.IndexFunc(host, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return nil, fmt.Errorf("embed: invalid TCP address %q", addr)
	}
	addr = net.JoinHostPort(host, strconv.Itoa(int(portOf(addr))))
	isOnion, err := onion.IsOnion(addr)
	if err != nil {
		return nil, err
	}
	if isOnion {
		if _, err := onion.NewFromString(addr); err != nil {
			return nil, err
		}
		return (&hs.Client{}).Connect(ctx, contextBuilder{ctx: ctx, lifetime: c.lifetime, builder: c.builder}, c.Consensus(), addr)
	}
	port := portOf(addr)
	// Retry with fresh circuits on transient stream/circuit failures, reusing
	// the pool when possible.
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pc, err := c.allocateCircuit(ctx, port)
		if err != nil {
			lastErr = err
			continue
		}
		// Only one dial owns a circuit at a time, so cancellation cannot
		// interrupt another caller's stream on a reused circuit.
		stop := context.AfterFunc(ctx, func() { c.invalidate(pc) })
		stream, err := pc.circ.NewStream(addr, pc.circ.HopCount()-1)
		stopped := stop()
		if !stopped || ctx.Err() != nil {
			if stream != nil {
				_ = stream.Free()
			}
			c.invalidate(pc)
			return nil, ctx.Err()
		}
		if err != nil {
			// The circuit is unhealthy; drop it and try another.
			c.invalidate(pc)
			lastErr = err
			continue
		}
		pc.uses.Add(1)
		return &pooledConn{Conn: stream.Conn(), client: c, pc: pc}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("embed: could not allocate a circuit for %s", addr)
	}
	return nil, lastErr
}

type pooledConn struct {
	net.Conn
	client *Client
	pc     *pooledCircuit
	once   sync.Once
	err    error
}

func (p *pooledConn) Close() error {
	p.once.Do(func() {
		p.err = p.Conn.Close()
		p.client.mu.Lock()
		p.pc.active = false
		p.client.mu.Unlock()
		p.client.reapOnce()
	})
	return p.err
}

// Dial is DialContext with a background context.
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, addr)
}

// DialTLSContext wraps the dialed connection in TLS (used as
// http.Transport.DialTLSContext so callers need no localhost/SOCKS proxy).
func (c *Client) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := c.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host := hostOf(addr)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func portOf(addr string) uint16 {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

// allocateCircuit returns a pooled (or freshly built) exit circuit, removing
// dead/invalid entries and respecting the pool TTL/use caps.
func (c *Client) allocateCircuit(ctx context.Context, port uint16) (*pooledCircuit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cns := c.Consensus()
	// Existing streams may drain, but a cached circuit must not bypass the
	// directory validity requirement for new traffic.
	if !cns.IsAuthenticated() || !cns.IsLive(time.Now()) {
		return nil, fmt.Errorf("embed: an authenticated live consensus is required")
	}
	c.reapOnce()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	// Clean invalid/expired entries and reuse a live one if available.
	var live *pooledCircuit
	kept := c.circuits[:0]
	for _, pc := range c.circuits {
		kept = append(kept, pc)
		if !pc.active && !pc.invalid.Load() && pc.circ.Ctx().Err() == nil && time.Now().Before(pc.expiresAt) && pc.port == port && pc.uses.Load() < c.useLimit() {
			live = pc
		}
	}
	c.circuits = kept
	if live != nil {
		live.active = true
	}
	c.mu.Unlock()

	if live != nil {
		return live, nil
	}

	circ, err := c.buildCircuit(ctx, cns, port)
	if err != nil {
		return nil, err
	}
	ttl := c.ttl
	if ttl == 0 {
		ttl = circuitTTL
	}
	pc := &pooledCircuit{
		circ:      circ,
		createdAt: time.Now(),
		expiresAt: time.Now().Add(ttl),
		active:    true,
		port:      port,
	}
	c.mu.Lock()
	if c.closed || ctx.Err() != nil {
		c.mu.Unlock()
		_ = circ.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, net.ErrClosed
	}
	c.circuits = append(c.circuits, pc)
	c.mu.Unlock()
	return pc, nil
}

func (c *Client) buildCircuit(ctx context.Context, cns *common.Consensus, port uint16) (capi.Circ, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sel := path.New(cns, c.longLived)
	if err := sel.SelectRandomCircuit(3, port); err != nil {
		return nil, fmt.Errorf("embed: select path: %w", err)
	}
	circ, err := (contextBuilder{ctx: ctx, lifetime: c.lifetime, builder: c.builder}).BuildPath(c.nextID.Add(1), sel.Circuit())
	if err != nil {
		return nil, err
	}
	return circ, nil
}

// invalidate marks a circuit for removal and closes it.
func (c *Client) invalidate(pc *pooledCircuit) {
	if pc.invalid.Swap(true) {
		return
	}
	_ = pc.circ.Close()
	c.mu.Lock()
	kept := c.circuits[:0]
	for _, other := range c.circuits {
		if other != pc {
			kept = append(kept, other)
		}
	}
	c.circuits = kept
	c.mu.Unlock()
}

// reapLoop proactively rotates expired circuits in the background.
func (c *Client) reapLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.conn.Context().Done():
			return
		case <-ticker.C:
			c.reapOnce()
		}
	}
}

// gonionBuilder adapts *gonion.Conn to capi.CircuitBuilder. Each BuildPath dials
// a fresh OR connection to the path's guard and builds the circuit there. This
// matches tor-spec: the circuit's first hop is the guard we are actually
// connected to, not whatever relay the bootstrap fallback happened to be.
type gonionBuilder struct {
	dial func(context.Context, *common.RouterStatus) (net.Conn, error)
	ctx  context.Context
}

func (b gonionBuilder) BuildPathContext(ctx context.Context, id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	b.ctx = ctx
	return b.BuildPath(id, relays)
}

func (b gonionBuilder) BuildPath(id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	if len(relays) == 0 {
		return nil, fmt.Errorf("embed: empty path")
	}
	if b.dial == nil {
		return nil, fmt.Errorf("embed: GuardDialer is required; refusing direct fallback")
	}
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if relays[0] == nil {
		return nil, fmt.Errorf("embed: nil guard")
	}
	raw, err := b.dial(ctx, relays[0])
	if err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("embed: GuardDialer returned nil connection")
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	conn, err := gonion.NewConn(raw, nil, false)
	if err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	stopBuild := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopBuild()
	circ, err := conn.BuildPath(id, relays)
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if !stopBuild() || !stop() || ctx.Err() != nil {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	context.AfterFunc(circ.Ctx, func() { _ = conn.Close() })
	return &guardCirc{Circ: gonion.NewCircAdapter(circ), conn: conn}, nil
}

// contextBuilder binds the legacy capi builder to one dial operation.
// The concrete embed builder can interrupt its owned OR connection.
// Other builders must return promptly; the legacy interface cannot cancel them.
type contextBuilder struct {
	ctx      context.Context
	lifetime context.Context
	builder  capi.CircuitBuilder
}

func (b contextBuilder) BuildPathContext(ctx context.Context, id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	b.ctx = ctx
	return b.BuildPath(id, relays)
}

func (b contextBuilder) BuildPath(id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	if b.builder == nil {
		return nil, fmt.Errorf("embed: no circuit builder")
	}
	var circ capi.Circ
	var err error
	if builder, ok := b.builder.(capi.ContextCircuitBuilder); ok {
		circ, err = builder.BuildPathContext(b.ctx, id, relays)
	} else {
		circ, err = b.builder.BuildPath(id, relays)
	}
	if b.ctx.Err() != nil {
		if circ != nil {
			_ = circ.Close()
		}
		return nil, b.ctx.Err()
	}
	if err == nil && circ != nil && b.lifetime != nil {
		stop := context.AfterFunc(b.lifetime, func() { _ = circ.Close() })
		context.AfterFunc(circ.Ctx(), func() { stop() })
		if b.lifetime.Err() != nil {
			_ = circ.Close()
			return nil, net.ErrClosed
		}
	}
	return circ, err
}

func (c *Client) useLimit() int64 {
	if c.maxUses == 0 {
		return maxCircuitUses
	}
	return c.maxUses
}

// path-spec 2.1.6: expiration prevents reuse, not delivery on active streams.
func (c *Client) reapOnce() {
	c.mu.Lock()
	var retired []capi.Circ
	kept := c.circuits[:0]
	for _, pc := range c.circuits {
		if pc.invalid.Load() || pc.circ.Ctx().Err() != nil || (!pc.active && (time.Now().After(pc.expiresAt) || pc.uses.Load() >= c.useLimit())) {
			retired = append(retired, pc.circ)
			continue
		}
		kept = append(kept, pc)
	}
	c.circuits = kept
	c.mu.Unlock()
	// Closing an OR connection may call application transport code. Never hold
	// the client mutex across that call: Close must still cancel pending work.
	for _, circ := range retired {
		_ = circ.Close()
	}
}

// guardCirc closes the underlying guard connection when the circuit is closed.
type guardCirc struct {
	capi.Circ
	conn *gonion.Conn
	once sync.Once
}

func (g *guardCirc) EstablishIntro(auth ed25519.PrivateKey) error {
	return g.Circ.(capi.ServiceCirc).EstablishIntro(auth)
}
func (g *guardCirc) JoinRendezvous(cookie [20]byte, reply, Kf, Kb, Df, Db []byte, address string) error {
	return g.Circ.(capi.ServiceCirc).JoinRendezvous(cookie, reply, Kf, Kb, Df, Db, address)
}
func (g *guardCirc) AcceptStream(ctx context.Context) (net.Conn, error) {
	return g.Circ.(capi.ServiceCirc).AcceptStream(ctx)
}
func (g *guardCirc) StopAccepting() error { return g.Circ.(capi.ServiceCirc).StopAccepting() }

func (g *guardCirc) Close() error {
	g.once.Do(func() { _ = g.conn.Close() })
	return g.Circ.Close()
}
