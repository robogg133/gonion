package embed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/internal/testutil/guardfixture"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/onion"
	"github.com/robogg133/gonion/pkg/path"
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
	failBuild       bool
	built           int
}

type testGuardBuilder struct {
	capi.CircuitBuilder
	guards *path.GuardManager
}

func (b testGuardBuilder) PublicGuardManager() *path.GuardManager { return b.guards }
func (b testGuardBuilder) CircuitGuard(ctx context.Context) (*common.RouterStatus, error) {
	if provider, ok := b.CircuitBuilder.(capi.GuardProvider); ok {
		return provider.CircuitGuard(ctx)
	}
	return nil, nil
}
func (b testGuardBuilder) BuildPathContext(ctx context.Context, id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	if builder, ok := b.CircuitBuilder.(capi.ContextCircuitBuilder); ok {
		return builder.BuildPathContext(ctx, id, relays)
	}
	return b.CircuitBuilder.BuildPath(id, relays)
}

func (b *stubBuilder) BuildPath(id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	if b.failBuild {
		return nil, errors.New("simulated circuit build failure")
	}
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

func newTestClient(t *testing.T, b capi.CircuitBuilder) *Client {
	t.Helper()
	c := &Client{cns: testutil.Consensus(t, time.Now()), builder: testGuardBuilder{CircuitBuilder: b, guards: guardfixture.Manager(t)}}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestAllocateCircuitPool(t *testing.T) {
	b := &stubBuilder{}
	c := newTestClient(t, b)

	ctx := context.Background()
	pc1, err := c.allocateCircuit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	first := b.last
	pc1.active = false // release the allocation before reusing it
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
	if !first.closed {
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
	c := newTestClient(t, b)

	pc, err := c.allocateCircuit(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	circ := b.last
	pc.active = false
	pc.expiresAt = time.Now().Add(-time.Minute)
	c.reapOnce()
	if !circ.closed {
		t.Fatal("expired circuit should be closed by reaper")
	}
	if len(c.circuits) != 0 {
		t.Fatalf("pool size after reap = %d, want 0", len(c.circuits))
	}
}

func TestHTTPClientWiring(t *testing.T) {
	c := newTestClient(t, &stubBuilder{})
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

// TestDialNonOnion exercises the full DialContext path for a plain address: it
// must allocate a pooled circuit, open a stream, and return a net.Conn whose
// writes go to that stream's cell sink.
func TestDialNonOnion(t *testing.T) {
	b := &stubBuilder{}
	c := newTestClient(t, b)

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
	c := newTestClient(t, b)
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
	c := newTestClient(t, b)

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

// --- E4.1: no skip-identity surface ---

// TestSkipIdentitySurfaceRemoved is the source-search proof required by E4.1:
// no file in this package, implementation or test, may reference any removed
// skip-identity field, the legacy context key, or any connection option that
// would decline relay identity verification. The identifiers are assembled at
// runtime so this test file never contains the literal sequences it forbids.
func TestSkipIdentitySurfaceRemoved(t *testing.T) {
	forbidden := []string{
		"Ignore" + "RelayCheck",
		"ORConnection" + "Skip" + "RelayFingerprintCheck",
		"GuardConnection" + "Skip" + "RelayFingerprintCheck",
		"CTXKey" + "SkipRelayIdentityCheck",
		"Conn" + "OptionSkipRelayFingerprintCheck",
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("package scan: %v (%d files)", err, len(files))
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, ident := range forbidden {
			if bytes.Contains(data, []byte(ident)) {
				t.Errorf("%s still references forbidden identifier %q", name, ident)
			}
		}
	}
}

type pinnedPipe struct {
	net.Conn
	id [20]byte
}

func (p pinnedPipe) ExpectedRelayIdentity() [20]byte { return p.id }

type recordingStorage struct{ calls atomic.Int32 }

func (r *recordingStorage) StoreConsensus(*common.Consensus) error { r.calls.Add(1); return nil }
func (r *recordingStorage) GetConsensus() (*common.Consensus, error) {
	r.calls.Add(1)
	return nil, nil
}

// TestConstructionFailClosedMatrix covers every public option-matrix entry
// that can be decided without network I/O: each one either constructs a
// supported configuration or fails closed before touching a socket, a
// dialer callback, or caller storage.
func TestConstructionFailClosedMatrix(t *testing.T) {
	t.Run("missing guards outside bridge mode", func(t *testing.T) {
		dials := 0
		opts := DefaultOptions()
		opts.ORDialer = func(context.Context) (net.Conn, error) { dials++; return nil, errors.New("unreachable") }
		if _, err := New(context.Background(), opts); !errors.Is(err, path.ErrGuardPersistence) || dials != 0 {
			t.Fatalf("missing guard persistence: %v dials=%d", err, dials)
		}
	})
	t.Run("cleared bootstrap dialer", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Guards = guardfixture.Manager(t)
		opts.ORDialer = nil
		if _, err := New(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "ORDialer is required") {
			t.Fatalf("cleared ORDialer: %v", err)
		}
	})
	t.Run("cleared guard dialer refuses fallback", func(t *testing.T) {
		b := gonionBuilder{guards: guardfixture.Manager(t)}
		if _, err := b.BuildPath(1, []*common.RouterStatus{{NodeID: [20]byte{1}}}); err == nil || !strings.Contains(err.Error(), "refusing direct fallback") {
			t.Fatalf("cleared GuardDialer fell back: %v", err)
		}
	})
	t.Run("conflicting bootstrap pins", func(t *testing.T) {
		raw, peer := net.Pipe()
		defer peer.Close()
		opts := DefaultOptions()
		opts.Guards = guardfixture.Manager(t)
		opts.BootstrapIdentity = [20]byte{1}
		_, err := NewWithConn(context.Background(), pinnedPipe{Conn: raw, id: [20]byte{2}}, opts)
		if err == nil || !strings.Contains(err.Error(), "conflicting bootstrap identity pins") {
			t.Fatalf("conflicting pins: %v", err)
		}
		if _, err := peer.Write([]byte{1}); err == nil {
			t.Fatal("rejected bootstrap connection leaked")
		}
	})
	t.Run("bridge pin conflicts with connection pin", func(t *testing.T) {
		raw, peer := net.Pipe()
		defer peer.Close()
		opts := DefaultBridgeOptions(BridgeOptions{Identity: [20]byte{1}, DialContext: func(context.Context) (net.Conn, error) { return nil, nil }})
		_, err := NewWithConn(context.Background(), pinnedPipe{Conn: raw, id: [20]byte{2}}, opts)
		if err == nil || !strings.Contains(err.Error(), "conflicting bootstrap identity pins") {
			t.Fatalf("bridge pin conflict: %v", err)
		}
		if _, err := peer.Write([]byte{1}); err == nil {
			t.Fatal("rejected bridge connection leaked")
		}
	})
	t.Run("zero identity is never a wildcard", func(t *testing.T) {
		raw, peer := net.Pipe()
		defer peer.Close()
		opts := DefaultOptions()
		opts.Guards = guardfixture.Manager(t)
		opts.BootstrapIdentity = [20]byte{} // the former skip field is gone
		if _, err := NewWithConn(context.Background(), raw, opts); err == nil || !strings.Contains(err.Error(), "identity is required") {
			t.Fatalf("unpinned bootstrap: %v", err)
		}
		if _, err := peer.Write([]byte{1}); err == nil {
			t.Fatal("rejected bootstrap connection leaked")
		}
	})
	t.Run("negative pool limits", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Guards = guardfixture.Manager(t)
		opts.CircuitTTL = -time.Second
		if _, err := New(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "negative circuit pool limit") {
			t.Fatalf("negative TTL: %v", err)
		}
		opts = DefaultOptions()
		opts.Guards = guardfixture.Manager(t)
		opts.MaxCircuitUses = -1
		if _, err := New(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "negative circuit pool limit") {
			t.Fatalf("negative use cap: %v", err)
		}
	})
	t.Run("storage is explicit and untouched on failure", func(t *testing.T) {
		if DefaultOptions().Storage != nil || DefaultBridgeOptions(BridgeOptions{Identity: [20]byte{1}}).Storage != nil {
			t.Fatal("a default must not select caller storage")
		}
		st := &recordingStorage{}
		raw, peer := net.Pipe()
		defer peer.Close()
		opts := DefaultOptions()
		opts.Guards = guardfixture.Manager(t)
		opts.Storage = st
		if _, err := NewWithConn(context.Background(), raw, opts); err == nil || !strings.Contains(err.Error(), "identity is required") {
			t.Fatalf("explicit storage with unpinned bootstrap: %v", err)
		}
		if st.calls.Load() != 0 {
			t.Fatal("construction touched caller storage before identity verification")
		}
	})
}

// --- E4.3: privacy-safe observability ---

func TestStatsSnapshotAndCounters(t *testing.T) {
	b := &stubBuilder{}
	c := newTestClient(t, b)
	c.obs = newObservability(nil) // silent counters; default remains Log==nil
	s := c.Stats()
	if !s.ConsensusPresent || !s.ConsensusAuthenticated || !s.ConsensusTrustedHydrated || !s.ConsensusLive || s.ConsensusRelays == 0 {
		t.Fatalf("consensus fields: %+v", s)
	}
	if s.GuardMode != "" || !s.BootstrappedAt.IsZero() || s.Closed {
		t.Fatalf("pre-bootstrap fields: %+v", s)
	}
	conn, err := c.Dial("tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	s = c.Stats()
	if s.CircuitsBuilt != 1 || s.CircuitBuildFailures != 0 || s.ActiveCircuits != 1 {
		t.Fatalf("after build: %+v", s)
	}
	_ = conn.Close()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	s = c.Stats()
	if !s.Closed || s.ActiveCircuits != 0 || s.Listeners != 0 || s.ListenerFaults != 0 {
		t.Fatalf("after close: %+v", s)
	}
	// A stale consensus is diagnosable from the snapshot without any new
	// networking: directory/recovery loss surfaces as age growth with
	// ConsensusLive false.
	c.cns = testutil.Consensus(t, time.Now().Add(-24*time.Hour))
	s = c.Stats()
	if s.ConsensusLive || s.ConsensusAge < 23*time.Hour {
		t.Fatalf("stale consensus not diagnosable: %+v", s)
	}
}

func TestStatsFailureClassesAreDiagnosable(t *testing.T) {
	b := &stubBuilder{failBuild: true}
	c := newTestClient(t, b)
	buf := &bytes.Buffer{}
	c.obs = newObservability(buf)
	if _, err := c.Dial("tcp", "topsecret.example.org:80"); err == nil {
		t.Fatal("expected build failure")
	}
	s := c.Stats()
	if s.CircuitBuildFailures == 0 || s.CircuitsBuilt != 0 {
		t.Fatalf("failure class: %+v", s)
	}
	log := buf.String()
	if !strings.Contains(log, "circuit: build failed") {
		t.Fatalf("log missing class: %q", log)
	}
	// Privacy: no destination label in logs or stats.
	if strings.Contains(log, "topsecret") || strings.Contains(fmt.Sprint(s), "topsecret") {
		t.Fatalf("destination leaked into observability: %q", log)
	}
}

func TestStatsGuardModes(t *testing.T) {
	// Guard dial failures count and classify without dialer internals.
	buf := &bytes.Buffer{}
	obs := newObservability(buf)
	want := errors.New("connection refused")
	b := gonionBuilder{dial: func(context.Context, *common.RouterStatus) (net.Conn, error) { return nil, want }, obs: obs}
	if _, err := b.BuildPath(1, []*common.RouterStatus{{NodeID: [20]byte{1}}}); !errors.Is(err, want) {
		t.Fatalf("dial error: %v", err)
	}
	if obs.guardDialFailures.Load() != 1 {
		t.Fatalf("guard dial failures: %d", obs.guardDialFailures.Load())
	}
	if log := buf.String(); !strings.Contains(log, "guard: dial failed") {
		t.Fatalf("missing guard class: %q", log)
	}
	// Pinned-bridge descriptor state feeds Stats.
	cns := testutil.Consensus(t, time.Now())
	d := &common.BridgeDescriptor{Relay: cns.RelayInformation[0], Expires: time.Now().Add(time.Hour)}
	bs := &bridgeState{identity: d.Relay.NodeID, lock: make(chan struct{}, 1), descriptor: d}
	bs.observe()
	c := newTestClient(t, &stubBuilder{})
	c.obs = newObservability(nil)
	c.guardMode = "pinned-bridge"
	c.bridge = bs
	s := c.Stats()
	if s.GuardMode != "pinned-bridge" || !s.BridgeDescriptorValid {
		t.Fatalf("bridge stats: %+v", s)
	}
	bs.observe() // retention is recomputed, not trusted from the caller.
	bs.descriptor.Expires = time.Now().Add(-time.Second)
	bs.observe()
	if valid, _ := bs.snapshot(); valid {
		t.Fatal("expired descriptor reported valid")
	}
}

// failingContextBuilder is reserved for onion-path failure injection.
type failingContextBuilder struct{ err error }

func (b failingContextBuilder) BuildPath(uint32, []*common.RouterStatus) (capi.Circ, error) {
	return nil, b.err
}
func (b failingContextBuilder) BuildPathContext(context.Context, uint32, []*common.RouterStatus) (capi.Circ, error) {
	return nil, b.err
}

func TestObservabilityListenerClassesCarryNoSecrets(t *testing.T) {
	c := newTestClient(t, &stubBuilder{})
	buf := &bytes.Buffer{}
	c.obs = newObservability(buf)
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	opts := ServiceOptions{Identity: identity, Port: 80, NextRevision: func(context.Context, [32]byte) (uint64, error) { return 1, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Listen(ctx, opts); err == nil {
		t.Fatal("expected onion maintenance failure offline")
	}
	log := buf.String()
	// Whatever the internal failure class (directory flags, builder, or
	// introduction), the log carries only fixed labels:
	if !strings.Contains(log, "listener: initialization starting") || !strings.Contains(log, "listener: initialization failed") {
		t.Fatalf("listener classes missing: %q", log)
	}
	onionHost := (&onion.OnionHostname{Pk: [32]byte(identity[32:]), Version: 3}).String()
	if strings.Contains(log, ".onion") || strings.Contains(log, onionHost) || strings.Contains(log, "circuit build failed offline") {
		t.Fatalf("listener detail leaked: %q", log)
	}
}

func TestObservabilityDefaultSilentAndFailureDiagnosable(t *testing.T) {
	if DefaultOptions().Log != nil || DefaultBridgeOptions(BridgeOptions{Identity: [20]byte{1}}).Log != nil {
		t.Fatal("defaults must not select a log writer")
	}
	want := errors.New("bridge unavailable")
	opts := DefaultBridgeOptions(BridgeOptions{Identity: [20]byte{1}, DialContext: func(context.Context) (net.Conn, error) { return nil, want }})
	buf := &bytes.Buffer{}
	opts.Log = buf
	if _, err := New(context.Background(), opts); !errors.Is(err, want) {
		t.Fatalf("bridge dial: %v", err)
	}
	if log := buf.String(); !strings.Contains(log, "bootstrap: dialing") || !strings.Contains(log, "bootstrap: dial failed") {
		t.Fatalf("bootstrap class missing: %q", log)
	}
	// A canceled initialization during a blocked bridge dial stays
	// attributable: the class line records the dial failure cause.
	blocking := DefaultBridgeOptions(BridgeOptions{Identity: [20]byte{1}, DialContext: func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	blocking.Log = buf
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := New(ctx, blocking); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled bootstrap: %v", err)
	}
	if log := buf.String(); !strings.Contains(log, "bootstrap: dial failed") {
		t.Fatalf("canceled bootstrap not diagnosable: %q", log)
	}
}
