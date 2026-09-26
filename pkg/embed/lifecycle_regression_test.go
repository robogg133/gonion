package embed

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

func TestDialerErrorClosesReturnedConnection(t *testing.T) {
	for _, kind := range []string{"bootstrap", "guard"} {
		t.Run(kind, func(t *testing.T) {
			raw, peer := net.Pipe()
			defer raw.Close()
			defer peer.Close()
			want := errors.New("dial failed after opening connection")
			var err error
			if kind == "bootstrap" {
				_, err = New(context.Background(), Options{ORDialer: func(context.Context) (net.Conn, error) { return raw, want }})
			} else {
				b := gonionBuilder{dial: func(context.Context, *common.RouterStatus) (net.Conn, error) { return raw, want }}
				_, err = b.BuildPath(1, []*common.RouterStatus{{}})
			}
			if !errors.Is(err, want) {
				t.Fatalf("dial error = %v, want %v", err, want)
			}
			_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("failed dial left a usable connection")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("failed dial leaked its connection")
			}
		})
	}
}

func TestGuardHandshakeReturnsContextError(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	b := gonionBuilder{dial: func(context.Context, *common.RouterStatus) (net.Conn, error) { return raw, nil }}
	_, err := b.BuildPathContext(ctx, 1, []*common.RouterStatus{{}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("guard handshake cancellation = %v, want deadline exceeded", err)
	}
}

type slowCloseCirc struct {
	*stubCirc
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *slowCloseCirc) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return nil
}

func TestReaperDoesNotHoldClientLockDuringClose(t *testing.T) {
	circ := &slowCloseCirc{stubCirc: &stubCirc{}, started: make(chan struct{}), release: make(chan struct{})}
	c := &Client{circuits: []*pooledCircuit{{circ: circ, expiresAt: time.Now().Add(-time.Hour)}}}
	reaped := make(chan struct{})
	go func() { c.reapOnce(); close(reaped) }()
	<-circ.started
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Error("reaper held client lock while closing a circuit")
	}
	close(circ.release)
	<-reaped
	<-closed
}

// tor-spec 6.2 requires a hostname or IP, not an empty host or control bytes.
func TestDialRejectsMalformedHostBeforeBuild(t *testing.T) {
	for _, addr := range []string{".:80", "bad\a.example:80", "bad\v.example:80", "bad\x7f.example:80", "[not:ipv6]:80", "bad\\host:80"} {
		t.Run(addr, func(t *testing.T) {
			b := &stubBuilder{}
			c := newTestClient(t, b)
			conn, err := c.Dial("tcp", addr)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil || b.built != 0 {
				t.Fatalf("malformed host reached circuit builder: builds=%d, err=%v", b.built, err)
			}
		})
	}
}

type pendingBuild struct {
	started chan struct{}
}

func (b *pendingBuild) BuildPath(uint32, []*common.RouterStatus) (capi.Circ, error) {
	return nil, errors.New("unexpected context-free build")
}

func (b *pendingBuild) BuildPathContext(ctx context.Context, _ uint32, _ []*common.RouterStatus) (capi.Circ, error) {
	b.started <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestConcurrentCloseCancelsDialAndListen(t *testing.T) {
	const operations = 12
	b := &pendingBuild{started: make(chan struct{}, operations)}
	c := newTestClient(t, b)
	opts := ServiceOptions{
		Identity: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		Port:     80,
		NextRevision: func(context.Context, [32]byte) (uint64, error) {
			return 0, errors.New("publication must not start")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, operations)
	for i := 0; i < operations; i++ {
		go func() {
			if i%2 == 0 {
				_, err := c.DialContext(ctx, "tcp", "example.com:80")
				done <- err
			} else {
				_, err := c.Listen(ctx, opts)
				done <- err
			}
		}()
	}
	for i := 0; i < operations; i++ {
		select {
		case <-b.started:
		case err := <-done:
			t.Fatalf("operation ended before circuit construction: %v", err)
		case <-ctx.Done():
			t.Fatal("operations did not reach circuit construction")
		}
	}
	var closers sync.WaitGroup
	for i := 0; i < operations; i++ {
		closers.Go(func() { _ = c.Close() })
	}
	closers.Wait()
	for i := 0; i < operations; i++ {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("pending operation returned %v, want cancellation", err)
			}
		case <-ctx.Done():
			t.Fatal("Client.Close did not cancel pending operation")
		}
	}
	if _, err := c.Dial("tcp", "example.com:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Dial after Close: %v", err)
	}
	if _, err := c.Listen(context.Background(), opts); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Listen after Close: %v", err)
	}
}
