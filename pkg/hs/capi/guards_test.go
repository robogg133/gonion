package capi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/path"
)

type guardTestCircuit struct {
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	closes, intros int
	streamOK       bool // when true NewStream succeeds instead of erroring
	recvOK         bool // when true RecvHSControl returns a control cell
}

func (c *guardTestCircuit) HopCount() int { return 3 }
func (c *guardTestCircuit) Ctx() context.Context {
	return c.ctx
}
func (c *guardTestCircuit) NewStream(string, int) (Stream, error) {
	if c.streamOK {
		return nil, nil
	}
	return nil, net.ErrClosed
}
func (c *guardTestCircuit) SendHSControl(relay.Cell) error { return nil }
func (c *guardTestCircuit) SetHSControl(chan relay.Cell)   {}
func (c *guardTestCircuit) RecvHSControl(ctx context.Context) (relay.Cell, error) {
	if c.recvOK {
		return nil, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *guardTestCircuit) AppendE2EHop([]byte, []byte, []byte, []byte) error { return nil }
func (c *guardTestCircuit) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	c.cancel()
	return nil
}
func (c *guardTestCircuit) EstablishIntro(ed25519.PrivateKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.intros++
	return nil
}
func (c *guardTestCircuit) JoinRendezvous([20]byte, []byte, []byte, []byte, []byte, []byte, string) error {
	return nil
}
func (c *guardTestCircuit) AcceptStream(context.Context) (net.Conn, error) { return nil, net.ErrClosed }
func (c *guardTestCircuit) StopAccepting() error                           { return nil }

type guardTestBuilder struct {
	guards    *path.GuardManager
	circ      *guardTestCircuit
	resultErr error
	selected  [20]byte
}

func (b *guardTestBuilder) PublicGuardManager() *path.GuardManager { return b.guards }
func (b *guardTestBuilder) BuildPath(_ uint32, relays []*common.RouterStatus) (Circ, error) {
	b.selected = relays[0].NodeID
	if b.resultErr != nil {
		return nil, b.resultErr
	}
	return b.circ, nil
}

func testGuardManager(t *testing.T, onSave func(int)) (*path.GuardManager, func() path.GuardSnapshot) {
	t.Helper()
	var mu sync.Mutex
	var raw []byte
	saves := 0
	m, err := path.NewGuardManager(context.Background(), path.GuardPersistence{
		Load: func(context.Context) ([]byte, error) { mu.Lock(); defer mu.Unlock(); return bytes.Clone(raw), nil },
		Save: func(_ context.Context, b []byte) error {
			mu.Lock()
			raw = bytes.Clone(b)
			saves++
			n := saves
			mu.Unlock()
			if onSave != nil {
				onSave(n)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// GuardPathBias accounting decisions are observable only through the
	// persisted snapshot this manager keeps.
	snap := func() path.GuardSnapshot {
		mu.Lock()
		defer mu.Unlock()
		var s path.GuardSnapshot
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Errorf("path: decoding persisted guard snapshot: %v", err)
		}
		return s
	}
	return m, snap
}

// biasRecord returns the path-bias counters persisted for one guard, or an
// empty record when the guard is not yet sampled.
func biasRecord(s path.GuardSnapshot, id [20]byte) path.GuardPathBias {
	for _, g := range s.Guards {
		if g.Identity == id {
			return g.PathBias
		}
	}
	return path.GuardPathBias{}
}

// guard-spec CIRC-STATUS/ON_SUCCESS: canceled circuits must not be returned
// to callers, even if a completed build is confirmed concurrently.
func TestGuardBuildCircuitDiesDuringConfirmation(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	life, cancel := context.WithCancel(context.Background())
	c := &guardTestCircuit{ctx: life, cancel: cancel}
	b := &guardTestBuilder{circ: c}
	b.guards, _ = testGuardManager(t, func(n int) {
		if n == 2 {
			cancel()
		}
	})
	got, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false)
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("dead circuit exposed: %T, %v", got, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closes != 1 {
		t.Fatalf("rejected circuit closed %d times", c.closes)
	}
}

func TestGuardBuildRejectsAlreadyDeadCircuit(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	life, cancel := context.WithCancel(context.Background())
	cancel()
	c := &guardTestCircuit{ctx: life, cancel: cancel}
	m, _ := testGuardManager(t, nil)
	b := &guardTestBuilder{circ: c, guards: m}
	got, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false)
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("dead circuit exposed: %T %v", got, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closes != 1 {
		t.Fatalf("rejected circuit closed %d times", c.closes)
	}
}

func TestGuardFailureIsNotInferredFromCancellationOrExtension(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"extension", errors.New("middle relay refused extension")},
		{"canceled first hop", &GuardConnectionFailure{Err: context.Canceled}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cns := testutil.Consensus(t, time.Now())
			m, bias := testGuardManager(t, nil)
			b := &guardTestBuilder{guards: m, resultErr: tc.err}
			if _, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false); !errors.Is(err, tc.err) {
				t.Fatalf("unexpected build result: %v", err)
			}
			if got := biasRecord(bias(), b.selected); got != (path.GuardPathBias{}) {
				t.Fatalf("non-guard failure counted against this circuit: %+v", got)
			}
			lease, err := m.Select(context.Background(), cns, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			if lease.Relay().NodeID != b.selected {
				t.Fatal("non-guard failure marked guard unreachable")
			}
		})
	}
}

func TestGuardConnectionFailureIsAttributedToSelectedGuard(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	m, bias := testGuardManager(t, nil)
	boom := errors.New("first-hop refused connection")
	b := &guardTestBuilder{guards: m, resultErr: &GuardConnectionFailure{Err: boom}}
	if _, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false); !errors.Is(err, boom) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := biasRecord(bias(), b.selected); got != (path.GuardPathBias{}) {
		t.Fatalf("guard connection failure counted against this circuit: %+v", got)
	}
	lease, err := m.Select(context.Background(), cns, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if lease.Relay().NodeID == b.selected {
		t.Fatal("failed first hop immediately retried")
	}
}

func TestGuardedServiceCircuitPreservesServiceInterface(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	life, cancel := context.WithCancel(context.Background())
	c := &guardTestCircuit{ctx: life, cancel: cancel}
	m, _ := testGuardManager(t, nil)
	b := &guardTestBuilder{circ: c, guards: m}
	got, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	service, ok := got.(ServiceCirc)
	if !ok {
		t.Fatalf("wrapped service circuit lost interface: %T", got)
	}
	if err := service.EstablishIntro(nil); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closes != 1 || c.intros != 1 {
		t.Fatalf("service wrapper close/intro: %d/%d", c.closes, c.intros)
	}
}

// testBuildProgressError carries the hop-progress signal *gonion.Conn reports
// from its extension loop besides the plain cause.
type testBuildProgressError struct {
	err  error
	hops int
}

func (e *testBuildProgressError) Error() string     { return e.err.Error() }
func (e *testBuildProgressError) Unwrap() error     { return e.err }
func (e *testBuildProgressError) PathBiasHops() int { return e.hops }

// path-spec §7.1: a construction attempt is credited only once the second hop
// has opened — a processed CREATED/EXTENDED reply (C circuit_finish_handshake).
// A guard-connection or first-hop handshake failure credits no attempt.
func TestPathBiasBuildAttemptedByHops(t *testing.T) {
	for _, tc := range []struct {
		name string
		hops int
		want path.GuardPathBias
	}{
		{"second hop opened", 2, path.GuardPathBias{CircAttempts: 1}},
		{"three hops opened", 3, path.GuardPathBias{CircAttempts: 1}},
		{"guard handshake only", 1, path.GuardPathBias{}},
		{"no hop opened", 0, path.GuardPathBias{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cns := testutil.Consensus(t, time.Now())
			m, bias := testGuardManager(t, nil)
			boom := errors.New("later hop refused the build")
			c := &guardTestCircuit{ctx: context.Background(), cancel: func() {}}
			b := &guardTestBuilder{guards: m, circ: c, resultErr: &testBuildProgressError{err: boom, hops: tc.hops}}
			if _, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false); !errors.Is(err, boom) {
				t.Fatalf("unexpected build result: %v", err)
			}
			if got := biasRecord(bias(), b.selected); got != tc.want {
				t.Fatalf("counters %+v, want %+v", got, tc.want)
			}
		})
	}
}

// guardTestContextBuilder exercises the ContextCircuitBuilder seam that owns
// the fixed 30s build deadline. It reports how many hops were open when the
// deadline fired, the per-hop progress the real builder carries.
type guardTestContextBuilder struct {
	guardTestBuilder
	hops int
}

func (b *guardTestContextBuilder) BuildPathContext(_ context.Context, _ uint32, relays []*common.RouterStatus) (Circ, error) {
	b.selected = relays[0].NodeID
	// A timed-out build reports the hops it had opened; a guard-connection
	// timeout that never opened a hop carries none.
	if b.hops == 0 {
		return nil, context.DeadlineExceeded
	}
	return nil, &testBuildProgressError{err: context.DeadlineExceeded, hops: b.hops}
}

// path-spec §7.1: a right-censored build timeout is a construction attempt
// only once the second hop opened; a timeout with no hop open is a guard
// connection failure, not path bias.
func TestPathBiasBuildTimedOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		hops int
		want path.GuardPathBias
	}{
		{"timeout with second hop opened", 2, path.GuardPathBias{CircAttempts: 1, Timeouts: 1}},
		{"timeout with no hop open", 0, path.GuardPathBias{Timeouts: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cns := testutil.Consensus(t, time.Now())
			m, bias := testGuardManager(t, nil)
			c := &guardTestCircuit{ctx: context.Background(), cancel: func() {}}
			b := &guardTestContextBuilder{guardTestBuilder{guards: m, circ: c}, tc.hops}
			if _, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unexpected build result: %v", err)
			}
			if got := biasRecord(bias(), b.selected); got != tc.want {
				t.Fatalf("counters %+v, want %+v", got, tc.want)
			}
		})
	}
}

// guardedTestCircuit returns a wrapped circuit whose completed build was
// confirmed under its own guard lease.
func guardedTestCircuit(t *testing.T) (Circ, *guardTestCircuit, [20]byte, func() path.GuardSnapshot) {
	t.Helper()
	cns := testutil.Consensus(t, time.Now())
	m, snap := testGuardManager(t, nil)
	life, cancel := context.WithCancel(context.Background())
	c := &guardTestCircuit{ctx: life, cancel: cancel}
	b := &guardTestBuilder{circ: c, guards: m}
	got, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return got, c, b.selected, snap
}

// guardedTestCircuitPurpose mirrors guardedTestCircuit but builds under a
// non-counted purpose, so the guard lease lifecycle runs while every
// path-bias counter stays at zero (C pathbias_should_count).
func guardedTestCircuitPurpose(t *testing.T, purpose path.BuildPurpose) (Circ, *guardTestCircuit, [20]byte, func() path.GuardSnapshot) {
	t.Helper()
	cns := testutil.Consensus(t, time.Now())
	m, snap := testGuardManager(t, nil)
	life, cancel := context.WithCancel(context.Background())
	c := &guardTestCircuit{ctx: life, cancel: cancel}
	b := &guardTestBuilder{circ: c, guards: m}
	got, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return got, c, b.selected, snap
}

// A circuit purpose excluded from path-bias accounting persists zero counters
// across its whole lifecycle while the guard lease still confirms the build
// and releases the circuit on Close.
func TestExcludedPurposePersistsNoCounters(t *testing.T) {
	for _, tc := range []struct {
		name    string
		purpose path.BuildPurpose
	}{
		{"rendezvous join", path.PurposeRendezvousJoin},
		{"client intro", path.PurposeClientIntro},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, c, id, snap := guardedTestCircuitPurpose(t, tc.purpose)
			// The usage attempt is exercised but must not persist a counter.
			if _, e := w.NewStream("dest.example.invalid", 1); e == nil {
				t.Fatal("expected stream error")
			}
			if e := w.Close(); e != nil {
				t.Fatal(e)
			}
			if got := biasRecord(snap(), id); got != (path.GuardPathBias{}) {
				t.Fatalf("excluded purpose persisted counters %+v", got)
			}
			c.mu.Lock()
			closes := c.closes
			c.mu.Unlock()
			if closes != 1 {
				t.Fatalf("inner circuit closed %d times", closes)
			}
		})
	}
}

// w.Close() is the classification switch, so the close kind must follow the
// usage state left on the wrapper (path-spec §7.2, C pathbias_check_close).
func TestPathBiasUsageLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(*guardTestCircuit)
		// exercise may shrink usage; the wrapper accounts the close.
		exercise func(t *testing.T, w Circ, c *guardTestCircuit)
		want     path.GuardPathBias
	}{
		{"attach-success", func(c *guardTestCircuit) { c.streamOK = true },
			func(t *testing.T, w Circ, _ *guardTestCircuit) {
				if _, e := w.NewStream("dest.example.invalid", 1); e != nil {
					t.Fatal(e)
				}
			},
			path.GuardPathBias{UseAttempts: 1, UseSuccesses: 1, CircAttempts: 1, CircSuccesses: 1, SuccessfulCircuitsClosed: 1}},
		{"attach-failure", nil,
			func(t *testing.T, w Circ, _ *guardTestCircuit) {
				if _, e := w.NewStream("dest.example.invalid", 1); e == nil {
					t.Fatal("expected stream error")
				}
			},
			path.GuardPathBias{UseAttempts: 1, CircAttempts: 1, CircSuccesses: 1, UnusableCircuits: 1}},
		{"provisional-rollback", func(c *guardTestCircuit) { c.streamOK = true },
			func(t *testing.T, w Circ, c *guardTestCircuit) {
				if _, e := w.NewStream("dest.example.invalid", 1); e != nil {
					t.Fatal(e)
				}
				c.streamOK = false
				// A later failed attachment clears the provisional success, so
				// the close is unusable rather than a finalized success.
				if _, e := w.NewStream("dest.example.invalid", 1); e == nil {
					t.Fatal("expected stream error")
				}
			},
			path.GuardPathBias{UseAttempts: 1, CircAttempts: 1, CircSuccesses: 1, UnusableCircuits: 1}},
		{"hs-control", func(c *guardTestCircuit) { c.recvOK = true },
			func(t *testing.T, w Circ, _ *guardTestCircuit) {
				if _, e := w.RecvHSControl(context.Background()); e != nil {
					t.Fatal(e)
				}
			},
			// Recognized HS control activity counts the implicit usage attempt
			// (C's strange start state) and finalizes the success at close.
			path.GuardPathBias{UseAttempts: 1, UseSuccesses: 1, CircAttempts: 1, CircSuccesses: 1, SuccessfulCircuitsClosed: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, c, id, snap := guardedTestCircuit(t)
			if tc.prep != nil {
				tc.prep(c)
			}
			tc.exercise(t, w, c)
			if e := w.Close(); e != nil {
				t.Fatal(e)
			}
			c.mu.Lock()
			closes := c.closes
			c.mu.Unlock()
			if closes != 1 {
				t.Fatalf("inner circuit closed %d times", closes)
			}
			if got := biasRecord(snap(), id); got != tc.want {
				t.Fatalf("counters %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The wrapper's own close, the natural-death hook and the lease accounting
// share the per-circuit once state: races and repeat closes count once.
func TestPathBiasCloseAccountedOnce(t *testing.T) {
	w, c, id, snap := guardedTestCircuit(t)
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	want := path.GuardPathBias{CircAttempts: 1, CircSuccesses: 1, SuccessfulCircuitsClosed: 1}
	if got := biasRecord(snap(), id); got != want {
		t.Fatalf("counters %+v, want %+v", got, want)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closes != 1 {
		t.Fatalf("inner circuit closed %d times", c.closes)
	}
}

// A circuit that dies before the client closes it is a collapsed close;
// the later client Close must not reclassify it.
func TestPathBiasPrematureCloseOnDeath(t *testing.T) {
	w, c, id, snap := guardedTestCircuit(t)
	c.cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := biasRecord(snap(), id).CollapsedCircuits; got == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("natural death was not accounted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	want := path.GuardPathBias{CircAttempts: 1, CircSuccesses: 1, CollapsedCircuits: 1}
	if got := biasRecord(snap(), id); got != want {
		t.Fatalf("counters %+v, want %+v", got, want)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closes != 1 {
		t.Fatalf("inner circuit closed %d times", c.closes)
	}
}

// Post-close attach and HS-control recognition are caller misuse: the
// accounted close must fence them out so they inject no counter event
// (path-spec §7.2 usage attempts occur on live circuits).
func TestPathBiasNoEventsAfterAccountedClose(t *testing.T) {
	w, c, id, snap := guardedTestCircuit(t)
	c.recvOK = true
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if _, err := w.NewStream("dest.example.invalid", 1); err == nil {
		t.Fatal("post-close attach unexpectedly succeeded")
	}
	if _, err := w.RecvHSControl(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := path.GuardPathBias{CircAttempts: 1, CircSuccesses: 1, SuccessfulCircuitsClosed: 1}
	if got := biasRecord(snap(), id); got != want {
		t.Fatalf("post-close misuse altered counters: %+v, want %+v", got, want)
	}
}

// A usage/close event whose save fails is not retried and stays unaccounted
// for that circuit; the close still returns the inner result cleanly, and the
// poisoned manager fails the next selection instead of building on lost state.
func TestPathBiasCloseEventLostOnFailedSave(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	life, cancel := context.WithCancel(context.Background())
	c := &guardTestCircuit{ctx: life, cancel: cancel}
	var mu sync.Mutex
	var raw []byte
	saves := 0
	m, err := path.NewGuardManager(context.Background(), path.GuardPersistence{
		Load: func(context.Context) ([]byte, error) {
			return bytes.Clone(raw), nil
		},
		Save: func(_ context.Context, data []byte) error {
			mu.Lock()
			defer mu.Unlock()
			saves++
			if saves > 3 {
				// The usage/close-event save is attempted and declines;
				// later attempts are not retried by accounting.
				return errors.New("disk full")
			}
			raw = bytes.Clone(data)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := &guardTestBuilder{guards: m, circ: c}
	w, _, err := BuildGuardedCircuit(context.Background(), b, cns, 1, 3, 80, nil, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if e := w.Close(); e != nil {
		t.Fatalf("close under a failing accounting save must report only the inner close result: %v", e)
	}
	mu.Lock()
	saved := saves
	var s path.GuardSnapshot
	err = json.Unmarshal(raw, &s)
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if saved != 4 {
		t.Fatalf("unexpected durable save attempts %d", saved)
	}
	// The close-event save failed and is not retried: construction counters
	// persisted, the close classification did not.
	if got := biasRecord(s, b.selected); got != (path.GuardPathBias{CircAttempts: 1, CircSuccesses: 1}) {
		t.Fatalf("failed close save altered counters: %+v", got)
	}
	// The poisoned manager refuses further work (fail-closed, no silent loss).
	if _, err := m.Select(context.Background(), cns, nil); err == nil {
		t.Fatal("poisoned manager still selected a guard")
	}
}
