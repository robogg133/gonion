package embed

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

// stubCirc is a no-op capi.Circ for pool tests.
type stubCirc struct {
	hops           int
	closed         bool
	failNextStream bool
	mu             sync.Mutex
}

func (s *stubCirc) HopCount() int        { return s.hops }
func (s *stubCirc) Ctx() context.Context { return context.Background() }
func (s *stubCirc) NewStream(target string, hopDest int) (capi.Stream, error) {
	if s.failNextStream {
		s.failNextStream = false
		return nil, fmt.Errorf("simulated stream failure")
	}
	return &stubStream{}, nil
}
func (s *stubCirc) SendHSControl(cell relay.Cell) error { return nil }
func (s *stubCirc) SetHSControl(ch chan relay.Cell)     {}
func (s *stubCirc) RecvHSControl(ctx context.Context) (relay.Cell, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *stubCirc) AppendE2EHop(Kf, Kb, Df, Db []byte) error { return nil }
func (s *stubCirc) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

type stubStream struct{}

func (s *stubStream) SendCell(cell relay.Cell) error { return nil }
func (s *stubStream) Recv(ctx context.Context) (relay.Cell, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *stubStream) Conn() net.Conn { return &nopConn{} }
func (s *stubStream) Free() error    { return nil }

// stubBuilder returns a fresh stubCirc each BuildPath call.
type stubBuilder struct {
	last            *stubCirc
	failFirstStream bool
	built           int
}

func (b *stubBuilder) BuildPath(id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	b.built++
	c := &stubCirc{hops: 3, failNextStream: b.failFirstStream}
	b.failFirstStream = false // only the first circuit fails its stream
	b.last = c
	return c, nil
}

// nopConn satisfies net.Conn.
type nopConn struct{}

func (n *nopConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (n *nopConn) Write([]byte) (int, error)        { return 0, nil }
func (n *nopConn) Close() error                     { return nil }
func (n *nopConn) LocalAddr() net.Addr              { return nil }
func (n *nopConn) RemoteAddr() net.Addr             { return nil }
func (n *nopConn) SetDeadline(time.Time) error      { return nil }
func (n *nopConn) SetReadDeadline(time.Time) error  { return nil }
func (n *nopConn) SetWriteDeadline(time.Time) error { return nil }

func testRelay(name string, port uint16) common.RouterStatus {
	flags := [15]bool{}
	flags[common.FLAG_EXIT] = true
	flags[common.FLAG_GUARD] = true
	flags[common.FLAG_FAST] = true
	flags[common.FLAG_STABLE] = true
	flags[common.FLAG_V2DIR] = true
	flags[common.FLAG_RUNNING] = true
	flags[common.FLAG_VALID] = true
	// NodeID, IdEd25519, NtorOnionKey required by haveAllKeys. IPLevel must be
	// unique so the path selector's family/16 check doesn't reject all.
	var nodeID [20]byte
	copy(nodeID[:], name)
	p := common.Ports{}
	p.SetPort(80, true) // allow exiting to :80, the port used by the dial tests
	p.SetPort(port, true)
	return common.RouterStatus{
		Nickname:     name,
		ORPort:       port,
		BandWidth:    1000,
		StatusFlags:  flags,
		NodeID:       nodeID,
		IdEd25519:    make([]byte, 32),
		NTorOnionKey: mustNtor(),
		IPLevel:      uint32(port), // distinct per relay
		Ports:        p,
	}
}

func mustNtor() *ecdh.PublicKey {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return sk.PublicKey()
}

func newTestClient(b capi.CircuitBuilder) *Client {
	return &Client{
		cns: &common.Consensus{
			RelayInformation: []common.RouterStatus{
				testRelay("a", 1),
				testRelay("b", 2),
				testRelay("c", 3),
				testRelay("d", 4),
			},
		},
		builder: b,
		hs:      nil, // not exercised by pool tests
	}
}

func TestAllocateCircuitPool(t *testing.T) {
	b := &stubBuilder{}
	c := newTestClient(b)

	ctx := context.Background()
	pc1, err := c.allocateCircuit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Second call should reuse the live circuit (under use cap).
	pc2, err := c.allocateCircuit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pc1 != pc2 {
		t.Fatal("expected pooled circuit reuse")
	}
	if len(c.circuits) != 1 {
		t.Fatalf("pool size = %d, want 1", len(c.circuits))
	}

	// Invalidate and ensure it is removed and a new one built.
	c.invalidate(pc1)
	if !pc1.circ.(*stubCirc).closed {
		t.Fatal("invalidated circuit should be closed")
	}
	pc3, err := c.allocateCircuit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pc3 == pc1 {
		t.Fatal("expected a fresh circuit after invalidation")
	}
	if len(c.circuits) != 1 {
		t.Fatalf("pool size after rotation = %d, want 1", len(c.circuits))
	}
}

func TestReapExpired(t *testing.T) {
	b := &stubBuilder{}
	c := newTestClient(b)

	pc, err := c.allocateCircuit(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	pc.expiresAt = time.Now().Add(-time.Minute)
	c.reapOnce()
	if !pc.circ.(*stubCirc).closed {
		t.Fatal("expired circuit should be closed by reaper")
	}
	if len(c.circuits) != 0 {
		t.Fatalf("pool size after reap = %d, want 0", len(c.circuits))
	}
}

func TestHTTPClientWiring(t *testing.T) {
	c := newTestClient(&stubBuilder{})
	hc := c.HTTPClient()
	if hc == nil || hc.Transport == nil {
		t.Fatal("HTTPClient must return a configured *http.Client")
	}
	// The transport must dial through this client.
	tr := hc.Transport.(*http.Transport)
	if tr.DialContext == nil {
		t.Fatal("transport DialContext not wired")
	}
}

// reapOnce runs a single passive reap pass (test helper; reuses reapLoop logic
// without the ticker).
func (c *Client) reapOnce() {
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

// TestDialNonOnion exercises the full DialContext path for a plain address: it
// must allocate a pooled circuit, open a stream, and return a net.Conn whose
// writes go to that stream's cell sink.
func TestDialNonOnion(t *testing.T) {
	b := &stubBuilder{}
	c := newTestClient(b)

	conn, err := c.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Fatal("nil conn")
	}
	// The pooled circuit must have been created and stored.
	if len(c.circuits) != 1 {
		t.Fatalf("pool size = %d, want 1", len(c.circuits))
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestDialOnionHostPortUsesHSPath(t *testing.T) {
	b := &stubBuilder{}
	c := newTestClient(b)
	c.hs = &hs.Client{}

	_, err := c.DialContext(context.Background(), "tcp", "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:80")
	if err == nil {
		t.Fatal("expected offline hidden-service setup to fail")
	}
	if b.built != 0 {
		t.Fatalf("onion destination used exit path (%d circuits built)", b.built)
	}
}

// TestDialRetryOnCircuitFailure checks that a stream error on an unhealthy
// circuit causes the client to invalidate it and retry on a fresh circuit,
// rather than returning the first error. The stub builder fails the first
// circuit's stream open, then succeeds on the second.
func TestDialRetryOnCircuitFailure(t *testing.T) {
	b := &stubBuilder{failFirstStream: true}
	c := newTestClient(b)

	conn, err := c.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("expected retry to succeed: %v", err)
	}
	if conn == nil {
		t.Fatal("nil conn after retry")
	}
	_ = conn.Close()
	// Two circuits must have been built: the failed one then the retry.
	if b.built < 2 {
		t.Fatalf("expected at least 2 circuit builds on retry, got %d", b.built)
	}
	if len(c.circuits) != 1 {
		t.Fatalf("pool should hold 1 (healthy) circuit after retry, got %d", len(c.circuits))
	}
}
