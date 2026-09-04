package embed

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

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
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("embed: unsupported network %q", network)
	}
	isOnion, err := onion.IsOnion(addr)
	if err != nil {
		return nil, err
	}
	if isOnion {
		return c.hs.Connect(ctx, gonionBuilder{}, c.Consensus(), addr)
	}
	port := portOf(addr)
	// Retry with fresh circuits on transient stream/circuit failures, reusing
	// the pool when possible.
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		pc, err := c.allocateCircuit(ctx, port)
		if err != nil {
			lastErr = err
			continue
		}
		stream, err := pc.circ.NewStream(addr, pc.circ.HopCount()-1)
		if err != nil {
			// The circuit is unhealthy; drop it and try another.
			c.invalidate(pc)
			lastErr = err
			continue
		}
		pc.uses.Add(1)
		// Watch the underlying circuit; if it dies, mark the pool entry stale.
		c.watchCircuit(pc)
		return stream.Conn(), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("embed: could not allocate a circuit for %s", addr)
	}
	return nil, lastErr
}

// watchCircuit marks pc invalid if its circuit context ends, so future dials
// avoid a dead circuit without waiting for the TTL reaper.
func (c *Client) watchCircuit(pc *pooledCircuit) {
	go func() {
		select {
		case <-pc.circ.Ctx().Done():
			c.invalidate(pc)
		}
	}()
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
	return tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}), nil
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
	c.mu.Lock()
	// Clean invalid/expired entries and reuse a live one if available.
	var live *pooledCircuit
	kept := c.circuits[:0]
	for _, pc := range c.circuits {
		if pc.invalid.Load() || time.Now().After(pc.expiresAt) {
			_ = pc.circ.Close()
			continue
		}
		kept = append(kept, pc)
		if pc.uses.Load() < maxCircuitUses {
			live = pc
		}
	}
	c.circuits = kept
	c.mu.Unlock()

	if live != nil {
		return live, nil
	}

	circ, err := c.buildCircuit(ctx, port)
	if err != nil {
		return nil, err
	}
	pc := &pooledCircuit{
		circ:      circ,
		createdAt: time.Now(),
		expiresAt: time.Now().Add(circuitTTL),
	}
	c.mu.Lock()
	c.circuits = append(c.circuits, pc)
	c.mu.Unlock()
	return pc, nil
}

func (c *Client) buildCircuit(ctx context.Context, port uint16) (capi.Circ, error) {
	cns := c.Consensus()
	sel := path.New(cns, c.longLived)
	if err := sel.SelectRandomCircuit(3, port); err != nil {
		return nil, fmt.Errorf("embed: select path: %w", err)
	}
	circ, err := c.builder.BuildPath(c.nextID.Add(1), sel.Circuit())
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
			c.mu.Lock()
			kept := c.circuits[:0]
			for _, pc := range c.circuits {
				if pc.invalid.Load() || time.Now().After(pc.expiresAt) {
					_ = pc.circ.Close()
					continue
				}
				kept = append(kept, pc)
			}
			c.circuits = kept
			c.mu.Unlock()
		}
	}
}

// gonionBuilder adapts *gonion.Conn to capi.CircuitBuilder. Each BuildPath dials
// a fresh OR connection to the path's guard and builds the circuit there. This
// matches tor-spec: the circuit's first hop is the guard we are actually
// connected to, not whatever relay the bootstrap fallback happened to be.
type gonionBuilder struct {
	// dial opens the TCP connection to a guard. When nil, a direct TCP dial to
	// the guard's OR address is used.
	dial func(guard *common.RouterStatus) (net.Conn, error)
}

func (b gonionBuilder) BuildPath(id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	if len(relays) == 0 {
		return nil, fmt.Errorf("embed: empty path")
	}
	dial := b.dial
	if dial == nil {
		dial = dialGuard
	}
	raw, err := dial(relays[0])
	if err != nil {
		return nil, err
	}
	conn, err := gonion.NewConn(raw, nil, false)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	circ, err := conn.BuildPath(id, relays)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &guardCirc{Circ: gonion.NewCircAdapter(circ), conn: conn}, nil
}

// dialGuard opens a direct TCP connection to the relay's OR port.
func dialGuard(r *common.RouterStatus) (net.Conn, error) {
	if r == nil || r.Ipv4Addr == "" || r.ORPort == 0 {
		return nil, fmt.Errorf("embed: guard %s missing OR address", r.Nickname)
	}
	// A short timeout caps wasted time on unreachable guards; the HS client
	// retries with fresh guards, so a reachable-one-first heuristic is enough.
	return net.DialTimeout("tcp", net.JoinHostPort(r.Ipv4Addr, strconv.Itoa(int(r.ORPort))), 6*time.Second)
}

// guardCirc closes the underlying guard connection when the circuit is closed.
type guardCirc struct {
	capi.Circ
	conn *gonion.Conn
	once sync.Once
}

func (g *guardCirc) Close() error {
	g.once.Do(func() { _ = g.conn.Close() })
	return g.Circ.Close()
}
