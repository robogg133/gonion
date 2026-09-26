package hs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/desc"
)

type publicationStream struct {
	capi.Stream
	conn net.Conn
}

func (s *publicationStream) Conn() net.Conn { return s.conn }
func (s *publicationStream) Free() error    { return s.conn.Close() }

type publicationCircuit struct {
	*lifecycleCircuit
	conn net.Conn
}

func (c *publicationCircuit) HopCount() int { return 3 }
func (c *publicationCircuit) NewStream(target string, hop int) (capi.Stream, error) {
	if target != "dir" || hop != 2 {
		return nil, fmt.Errorf("unexpected directory stream target")
	}
	return &publicationStream{conn: c.conn}, nil
}
func (c *publicationCircuit) Close() error {
	c.cancel()
	return c.conn.Close()
}

func TestServicePartialPublicationRetainsIntrosAndRevision(t *testing.T) {
	// EXPIRE-DESC / DESC-OUTER: even one acknowledged upload makes these
	// introductions usable for 180 minutes and consumes the revision.
	cns := testutil.Consensus(t, time.Now())
	d := maintenanceDescriptor(t, servicePeriods(cns)[0])
	// Encoding no introductions is valid at this lower-level API; circuit
	// health/three-introduction readiness is enforced by renewal separately.
	d.intros = nil
	groups := [][]common.RouterStatus{{cns.RelayInformation[0]}, {cns.RelayInformation[1]}}
	for i := range groups {
		groups[i][0].StatusFlags[common.FLAG_HIDDEN_SERVICE_DIR] = true
		groups[i][0].ProtoVersions.HSDir.SetValue(common.VERSION_2, true)
	}
	var peers sync.WaitGroup
	defer peers.Wait()
	var revision uint64 = 7
	l := &Listener{revisions: make(map[[32]byte]uint64)}
	l.opts.NextRevision = func(context.Context, [32]byte) (uint64, error) { return revision, nil }
	l.builder = serviceBuildFunc(func(_ context.Context, relays []*common.RouterStatus) (capi.Circ, error) {
		conn, peer := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		circ := &publicationCircuit{lifecycleCircuit: &lifecycleCircuit{ctx: ctx, cancel: cancel}, conn: conn}
		status := http.StatusOK
		if relays[len(relays)-1].NodeID == groups[1][0].NodeID {
			status = http.StatusServiceUnavailable
		}
		peers.Add(1)
		go func() {
			defer peers.Done()
			defer peer.Close()
			_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
			req, err := http.ReadRequest(bufio.NewReader(peer))
			if err != nil {
				t.Error(err)
				return
			}
			raw, err := io.ReadAll(req.Body)
			_ = req.Body.Close()
			if err != nil {
				t.Error(err)
				return
			}
			parsed, err := desc.Parse(raw)
			if err != nil || parsed.RevisionCounter != 7 || req.Method != http.MethodPost || req.URL.Path != "/tor/hs/3/publish" {
				t.Errorf("unexpected publication: %v", err)
				return
			}
			_, _ = fmt.Fprintf(peer, "HTTP/1.0 %d result\r\nContent-Length: 0\r\n\r\n", status)
		}()
		return circ, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before := time.Now()
	if err := l.publish(ctx, cns, d, groups); err == nil {
		t.Fatal("partial publication reported readiness")
	}
	if d.published.Before(before) || !d.nextPublication.IsZero() {
		t.Fatal("partial upload lost retention or suppressed retries")
	}
	if err := l.publish(ctx, cns, d, groups); err == nil || !strings.Contains(err.Error(), "did not increase") {
		t.Fatalf("reused partially published revision: %v", err)
	}
	l.retired = []*serviceDescriptor{d}
	l.pruneRetired(d.published.Add(3*time.Hour - time.Nanosecond))
	if len(l.retired) != 1 {
		t.Fatal("partially published descriptor retired early")
	}
	l.pruneRetired(d.published.Add(3 * time.Hour))
	if len(l.retired) != 0 {
		t.Fatal("expired partial publication retained")
	}
}

func TestServiceEncodingFailureConsumesRevision(t *testing.T) {
	d := maintenanceDescriptor(t, descriptorPeriod{16903, 1440})
	d.signing = nil
	l := &Listener{revisions: make(map[[32]byte]uint64), opts: ServiceOptions{
		NextRevision: func(context.Context, [32]byte) (uint64, error) { return 42, nil },
	}}
	if err := l.publish(context.Background(), nil, d, nil); err == nil {
		t.Fatal("invalid signing key accepted")
	}
	if err := l.publish(context.Background(), nil, d, nil); err == nil || !strings.Contains(err.Error(), "did not increase") {
		t.Fatalf("failed encoding reused reserved revision: %v", err)
	}
}

type queuedServiceCircuit struct {
	*lifecycleCircuit
	streams chan net.Conn
}

func (c *queuedServiceCircuit) AcceptStream(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-c.streams:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestServiceIncomingQueueOverflowAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	circCtx, circCancel := context.WithCancel(context.Background())
	defer circCancel()
	circ := &queuedServiceCircuit{lifecycleCircuit: &lifecycleCircuit{ctx: circCtx, cancel: circCancel}, streams: make(chan net.Conn, 65)}
	l := &Listener{ctx: ctx, cancel: cancel, incoming: make(chan net.Conn, 64), rendezvous: map[capi.ServiceCirc]struct{}{circ: {}}}
	defer l.Shutdown()
	var peers []net.Conn
	for i := 0; i <= cap(l.incoming); i++ {
		conn, peer := net.Pipe()
		t.Cleanup(func() { conn.Close(); peer.Close() })
		circ.streams <- conn
		peers = append(peers, peer)
	}
	done := make(chan struct{})
	go func() { l.acceptRendezvous(circ); close(done) }()
	overflow := peers[len(peers)-1]
	_ = overflow.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := overflow.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("overflow stream was not closed: %v", err)
	}
	if len(l.incoming) != cap(l.incoming) {
		t.Fatal("incorrect pending stream bound")
	}
	_ = l.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept producer survived listener close")
	}
	if len(l.incoming) != 0 || !circ.stopped.Load() || circCtx.Err() != nil {
		t.Fatal("Close did not drain pending streams or killed the rendezvous")
	}
	for _, peer := range peers {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("pending stream survived Close: %v", err)
		}
	}
}
