package embed

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

func TestDefaultsAndNoDirectFallback(t *testing.T) {
	o := DefaultOptions()
	if o.Storage != nil || o.CircuitTTL != 10*time.Minute || o.MaxCircuitUses != 100 {
		t.Fatal("unexpected policy defaults")
	}
	// The direct-TCP bootstrap and guard dialers are ordinary visible options,
	// not a fallback the library reinstates after a caller clears one.
	if o.ORDialer == nil || o.GuardDialer == nil {
		t.Fatal("default dialers must be supplied in the options")
	}
	// The default guard dialer must reach the relay that was selected for this
	// circuit, never a substitute.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	guard := &common.RouterStatus{Ipv4Addr: "127.0.0.1", ORPort: uint16(listener.Addr().(*net.TCPAddr).Port)}
	conn, err := o.GuardDialer(context.Background(), guard)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = accepted.Close()
	// A caller that clears the dialers must fail closed.
	_, err = (gonionBuilder{}).BuildPath(1, []*common.RouterStatus{{}})
	if err == nil || !strings.Contains(err.Error(), "refusing direct fallback") {
		t.Fatalf("missing fail-closed guard: %v", err)
	}
}

func TestDialRejectsBeforeBuild(t *testing.T) {
	for _, addr := range []string{"example.com", ":80", "example.com:0", "example.com:65536", "example.com:http", "a\x00b:80", "bad.onion:80", "bad.ONION.:80", "[::1]:80"} {
		t.Run(addr, func(t *testing.T) {
			b := &stubBuilder{}
			_, err := newTestClient(t, b).DialContext(context.Background(), "tcp", addr)
			if err == nil || b.built != 0 {
				t.Fatalf("address accepted or circuit built: %v", err)
			}
		})
	}
	b := &stubBuilder{}
	c := newTestClient(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.Canceled) || b.built != 0 {
		t.Fatalf("cancellation: %v", err)
	}
	_ = c.Close()
	if _, err := c.Dial("tcp", "example.com:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed dial: %v", err)
	}
}

// path-spec 2.2.1 requires a supporting exit for each requested port.
func TestPoolDoesNotReuseDifferentPort(t *testing.T) {
	c := newTestClient(t, &stubBuilder{})
	first, err := c.allocateCircuit(context.Background(), 80)
	if err != nil {
		t.Fatal(err)
	}
	first.active = false
	second, err := c.allocateCircuit(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("reused a circuit selected for another port")
	}
	_ = c.Close()
}

// path-spec 2.1.6 and tor-spec 5.4: lifetime expiration must drain streams.
func TestExpiredActiveCircuitDrains(t *testing.T) {
	c := newTestClient(t, &stubBuilder{})
	conn, err := c.Dial("tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	pc := c.circuits[0]
	pc.expiresAt = time.Now().Add(-time.Second)
	c.reapOnce()
	if pc.circ.(*stubCirc).closed {
		t.Fatal("active stream closed at TTL")
	}
	next, err := c.Dial("tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.circuits) != 2 {
		t.Fatal("expired active circuit reused")
	}
	_ = conn.Close()
	_ = conn.Close()
	if !pc.circ.(*stubCirc).closed {
		t.Fatal("drained expired circuit not closed")
	}
	_ = next.Close()
	_ = c.Close()
}

type blockingCirc struct {
	*stubCirc
	ctx     context.Context
	cancel  context.CancelFunc
	started chan struct{}
}

func (b *blockingCirc) Ctx() context.Context { return b.ctx }
func (b *blockingCirc) Close() error         { b.cancel(); return b.stubCirc.Close() }
func (b *blockingCirc) NewStream(string, int) (capi.Stream, error) {
	close(b.started)
	<-b.ctx.Done()
	return nil, b.ctx.Err()
}

func TestCancelPendingStream(t *testing.T) {
	lifetime, finish := context.WithCancel(context.Background())
	defer finish()
	circ := &blockingCirc{stubCirc: &stubCirc{hops: 3}, ctx: lifetime, cancel: finish, started: make(chan struct{})}
	c := newTestClient(t, &stubBuilder{})
	c.circuits = []*pooledCircuit{{circ: circ, port: 80, expiresAt: time.Now().Add(time.Hour)}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.DialContext(ctx, "tcp", "example.com:80"); done <- err }()
	<-circ.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream open ignored cancellation")
	}
}

func TestTLSHandshakeFailureReleasesStream(t *testing.T) {
	c := newTestClient(t, &stubBuilder{})
	conn, err := c.DialTLSContext(context.Background(), "tcp", "example.com:80")
	if err == nil || conn != nil {
		t.Fatal("TLS returned before handshake")
	}
	if c.circuits[0].active {
		t.Fatal("failed TLS left stream reserved")
	}
	_ = c.Close()
}

func TestPoolRequiresAuthenticatedLiveConsensus(t *testing.T) {
	for _, state := range []string{"missing", "untrusted", "expired", "future"} {
		t.Run(state, func(t *testing.T) {
			b := &stubBuilder{}
			c := newTestClient(t, b)
			conn, err := c.Dial("tcp", "example.com:80")
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			switch state {
			case "missing":
				c.cns = nil
			case "untrusted":
				c.cns = &common.Consensus{ValidAfter: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
			case "expired":
				c.cns = testutil.Consensus(t, time.Now().Add(-24*time.Hour))
			case "future":
				c.cns = testutil.Consensus(t, time.Now().Add(24*time.Hour))
			}
			if _, err := c.Dial("tcp", "example.com:80"); err == nil || b.built != 1 || c.circuits[0].active {
				t.Fatalf("invalid consensus reused or built a circuit: %v", err)
			}
		})
	}
}

func TestBootstrapRequiresIdentityBeforeIO(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	if _, err := NewWithConn(context.Background(), raw, DefaultOptions()); err == nil || !strings.Contains(err.Error(), "identity is required") {
		t.Fatalf("unpinned bootstrap: %v", err)
	}
	if _, err := peer.Write([]byte{1}); err == nil {
		t.Fatal("rejected bootstrap connection leaked")
	}
}

func TestBootstrapHandshakeCancellation(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	opts := DefaultOptions()
	opts.BootstrapIdentity = [20]byte{1}
	_, err := NewWithConn(ctx, raw, opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handshake cancellation: %v", err)
	}
}
