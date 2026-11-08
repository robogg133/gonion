package gonion

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/internal/window"
	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	cryptopkg "github.com/robogg133/gonion/pkg/crypto"
	"github.com/robogg133/gonion/pkg/handshakes"
	"github.com/robogg133/gonion/pkg/lspec"
)

type testDestroy struct {
	id     uint32
	reason uint8
}

// newTestConn builds the state a live link would own without performing TLS.
func newTestConn(t *testing.T) *Conn {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	conn := &Conn{
		ctx:            ctx,
		ctxCancel:      cancel,
		writeCall:      make(chan cellWrite, 64),
		circuits:       &circuits{circs: make(map[uint32]*Circuit)},
		circuitIDs:     make(map[uint32]struct{}),
		ProtcolVersion: 4,
		cellBodyLen:    cells.CELL_BODY_LEN,
		circIDRand:     rand.Reader,
	}
	t.Cleanup(func() { cancel(net.ErrClosed) })
	return conn
}

// serveFast replies to CREATE_FAST and records DESTROY cells. No TLS or public
// relay is involved.
func serveFast(t *testing.T, conn *Conn, silent bool, destroys chan<- testDestroy) {
	t.Helper()
	coder := cells.NewCellCoder(cells.AllKnownCells)
	go func() {
		for {
			select {
			case <-conn.ctx.Done():
				return
			case write := <-conn.writeCall:
				cell, err := coder.ReadCell(bytes.NewReader(write.data))
				if err == nil {
					switch typed := cell.(type) {
					case *cells.CreateFastCell:
						if !silent {
							var y [20]byte
							for i := range y {
								y[i] = byte(i + 1)
							}
							keys, derr := cryptopkg.DeriveKeysCreateFast(typed.X, y)
							if derr == nil {
								raw := make([]byte, 5+cells.CELL_BODY_LEN)
								binary.BigEndian.PutUint32(raw[0:4], typed.CircuitID)
								raw[4] = cells.COMMAND_CREATED_FAST
								copy(raw[5:25], y[:])
								copy(raw[25:45], keys.KH)
								if circuit := conn.circuits.Get(typed.CircuitID); circuit != nil {
									select {
									case circuit.Inbound <- raw:
									case <-conn.ctx.Done():
										return
									}
								}
							}
						}
					case *cells.DestroyCell:
						if destroys != nil {
							select {
							case destroys <- testDestroy{id: typed.CircuitID, reason: typed.Reason}:
							default:
							}
						}
					}
				}
				select {
				case write.done <- nil:
				default:
				}
			}
		}
	}()
}

func buildFast(t *testing.T, conn *Conn) *Circuit {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	circuit, err := conn.NewFastCircuitContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return circuit
}

func TestCircuitTeardownDestroysAndReleasesState(t *testing.T) {
	conn := newTestConn(t)
	destroys := make(chan testDestroy, 8)
	serveFast(t, conn, false, destroys)

	circuit := buildFast(t, conn)
	stream, err := circuit.reserveStream("example.com:80", 0)
	if err != nil {
		t.Fatal(err)
	}
	id := circuit.ID

	if err := circuit.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-destroys:
		if got.id != id || got.reason != cells.DESTROY_REASON_NONE {
			t.Fatalf("DESTROY = %#v, want id %#x reason 0", got, id)
		}
	case <-time.After(time.Second):
		t.Fatal("local Close did not emit DESTROY")
	}
	if conn.circuits.Get(id) != nil {
		t.Fatal("registry entry survived Close")
	}
	if circuit.streams.Len() != 0 {
		t.Fatal("stream registry survived Close")
	}
	if stream.Ctx.Err() == nil {
		t.Fatal("stream ownership survived Close")
	}

	// Repeated Close is idempotent: no second DESTROY and no state change.
	if err := circuit.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-destroys:
		t.Fatalf("duplicate DESTROY: %#v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRemoteDestroyCannotDeleteNewerCircuit(t *testing.T) {
	conn := newTestConn(t)
	const id = uint32(0x80000011)

	old := manualCircuit(conn, id, 4)
	newer := manualCircuit(conn, id, 4)
	if !conn.circuits.Add(id, newer) {
		t.Fatal("failed to install newer circuit")
	}
	// A delayed teardown of the old value must not remove the newer entry.
	if conn.circuits.DeleteIf(id, old) {
		t.Fatal("DeleteIf removed a different circuit")
	}
	if got := conn.circuits.Get(id); got != newer {
		t.Fatal("newer circuit was replaced or deleted")
	}
	old.teardown(Public(ErrCircuit, "remote destroy"), cells.DESTROY_REASON_NONE, false)
	if got := conn.circuits.Get(id); got != newer {
		t.Fatal("late teardown deleted a newer circuit")
	}
	if newer.Ctx.Err() != nil {
		t.Fatal("late teardown canceled a newer circuit")
	}
}

func TestCircuitBuildFailureCleansRegistry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{name: "silent peer deadline"},
		{name: "caller cancellation", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newTestConn(t)
			destroys := make(chan testDestroy, 4)
			serveFast(t, conn, true, destroys)

			var ctx context.Context
			var cancel context.CancelFunc
			if tc.cancel {
				ctx, cancel = context.WithCancel(context.Background())
				time.AfterFunc(20*time.Millisecond, cancel)
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}
			defer cancel()

			if _, err := conn.NewFastCircuitContext(ctx); err == nil {
				t.Fatal("silent peer did not fail the build")
			}
			if conn.circuits.Len() != 0 {
				t.Fatal("failed build left a registry entry")
			}
			conn.circIDMu.Lock()
			reserved := len(conn.circuitIDs)
			conn.circIDMu.Unlock()
			if reserved != 0 {
				t.Fatalf("failed build left %d id reservations", reserved)
			}
			select {
			case got := <-destroys:
				t.Fatalf("unestablished circuit sent DESTROY: %#v", got)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

func TestCircuitBuildCloseCyclesDoNotLeak(t *testing.T) {
	conn := newTestConn(t)
	destroys := make(chan testDestroy, 32)
	serveFast(t, conn, false, destroys)
	baseline := runtime.NumGoroutine()

	const cycles = 10000
	for i := 0; i < cycles; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		circuit, err := conn.NewFastCircuitContext(ctx)
		cancel()
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if err := circuit.Close(); err != nil {
			t.Fatalf("cycle %d close: %v", i, err)
		}
	}
	if got := conn.circuits.Len(); got != 0 {
		t.Fatalf("%d registry entries survived %d cycles", got, cycles)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+16 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+16 {
		t.Fatalf("goroutines grew from %d to %d after %d cycles", baseline, got, cycles)
	}
}

func TestCircuitIDAllocationRules(t *testing.T) {
	if id, err := shared.RandomCircID(bytes.NewReader([]byte{0x12, 0x34}), 3); err != nil || id != 0x1234 {
		t.Fatalf("v3 id = %#x, %v", id, err)
	}
	if id, err := shared.RandomCircID(bytes.NewReader([]byte{0, 0, 0, 1}), 4); err != nil || id != 0x80000001 {
		t.Fatalf("v4 id = %#x, %v", id, err)
	}

	conn := newTestConn(t)
	conn.ProtcolVersion = 3
	// Two zero draws are rejected, then a nonzero two-byte ID is accepted.
	conn.circIDRand = bytes.NewReader([]byte{0, 0, 0, 0, 0x12, 0x34})
	id, err := conn.allocCircID()
	if err != nil || id != 0x1234 {
		t.Fatalf("alloc after zero = %#x, %v", id, err)
	}

	// A deterministic source that always collides must exhaust without
	// replacing or disturbing the reserved circuit.
	collide := newTestConn(t)
	collide.circIDRand = bytes.NewReader(bytes.Repeat([]byte{0, 0, 0, 9}, shared.CIRCUIT_ID_MAX_RETRIES+1))
	first, err := collide.allocCircID()
	if err != nil {
		t.Fatal(err)
	}
	if first&0x80000000 == 0 {
		t.Fatalf("v4 id %#x lacks the MSB", first)
	}
	_, err = collide.allocCircID()
	var exhausted *CircuitIDExhaustedError
	if !errors.As(err, &exhausted) || exhausted.Attempts != shared.CIRCUIT_ID_MAX_RETRIES {
		t.Fatalf("collision error = %v", err)
	}
	if _, ok := collide.circuitIDs[first]; !ok {
		t.Fatal("exhaustion disturbed the existing reservation")
	}

	// Registration never replaces a live entry with the same ID.
	existing := manualCircuit(collide, first, 1)
	collide.circuits.Add(first, existing)
	replacement := manualCircuit(collide, first, 1)
	if err := collide.registerCircuit(replacement); err == nil {
		t.Fatal("registerCircuit replaced a live entry")
	}
	if got := collide.circuits.Get(first); got != existing {
		t.Fatal("existing circuit was replaced")
	}

	// Sequential-looking hints do not determine allocation.
	hint := newTestConn(t)
	hint.circIDRand = bytes.NewReader([]byte{0, 0, 0, 2, 0, 0, 0, 3})
	a, err := hint.allocCircID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := hint.allocCircID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || a != 0x80000002 || b != 0x80000003 {
		t.Fatalf("non-deterministic allocation = %#x, %#x", a, b)
	}
}

func TestCircuitAndStreamCeilings(t *testing.T) {
	conn := newTestConn(t)
	conn.maxCircuits = 2
	ctx := context.Background()

	first, stop, err := conn.newCircuitContext(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	second, stop, err := conn.newCircuitContext(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	_, _, err = conn.newCircuitContext(ctx, "test")
	var limit *CircuitLimitError
	if !errors.As(err, &limit) || limit.Limit != 2 {
		t.Fatalf("circuit limit error = %v", err)
	}
	if conn.circuits.Len() != 2 {
		t.Fatal("circuit limit was not enforced exactly")
	}
	_ = first.Close()
	_ = second.Close()

	circuit, stop, err := conn.newCircuitContext(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	defer circuit.Close()
	circuit.maxStreams = 2
	s1, err := circuit.reserveStream("a:1", 0)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := circuit.reserveStream("b:2", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = circuit.reserveStream("c:3", 0)
	var streamLimit *StreamLimitError
	if !errors.As(err, &streamLimit) || streamLimit.Limit != 2 {
		t.Fatalf("stream limit error = %v", err)
	}
	_ = s1.Free()
	_ = s2.Free()

	if cap(circuit.Inbound) != maxCircuitInboundCells ||
		cap(circuit.WriteRelayCell) != maxCircuitOutboundCells ||
		cap(circuit.writeControl) != maxCircuitControlCells {
		t.Fatal("circuit queue ceilings are not applied")
	}
	if MaxCircuitInboundBytes != maxCircuitInboundCells*(cells.CELL_BODY_LEN+5) ||
		MaxQueuedLinkBytes != maxQueuedLinkCells*(cells.CELL_BODY_LEN+5) {
		t.Fatal("byte ceilings do not match cell ceilings")
	}
	if circuit.reserveInbound(MaxCircuitInboundBytes) {
		circuit.releaseInbound(MaxCircuitInboundBytes)
	}
	if circuit.reserveInbound(MaxCircuitInboundBytes + 1) {
		t.Fatal("circuit inbound byte ceiling was not enforced")
	}
}

func manualCircuit(conn *Conn, id uint32, inbound int) *Circuit {
	ctx, cancel := context.WithCancelCause(conn.ctx)
	circuit := &Circuit{
		conn:           conn,
		ID:             id,
		Ctx:            ctx,
		ctxCancel:      cancel,
		Inbound:        make(chan []byte, inbound),
		WriteRelayCell: make(chan RelayOut, 8),
		writeControl:   make(chan RelayOut, 8),
		streams:        &streams{streams: make(map[uint16]*Stream)},
		Coder:          cells.NewCellCoder(cells.AllKnownCells),
	}
	circuit.established.Store(true)
	return circuit
}

func testFrame(id uint32) []byte {
	frame := make([]byte, 5+cells.CELL_BODY_LEN)
	binary.BigEndian.PutUint32(frame, id)
	frame[4] = cells.COMMAND_RELAY
	return frame
}

func TestSaturatedCircuitDoesNotStallReadLoop(t *testing.T) {
	local, peer := net.Pipe()
	conn := newTestConn(t)
	conn.socket = local
	defer peer.Close()

	saturated := manualCircuit(conn, 0x80000021, 0)
	healthy := manualCircuit(conn, 0x80000022, 4)
	conn.circuits.Add(saturated.ID, saturated)
	conn.circuits.Add(healthy.ID, healthy)
	go conn.readLoop()

	go func() {
		_, _ = peer.Write(testFrame(saturated.ID))
		_, _ = peer.Write(testFrame(healthy.ID))
	}()

	select {
	case <-healthy.Inbound:
	case <-time.After(2 * time.Second):
		t.Fatal("saturated circuit stalled an unrelated circuit")
	}
	select {
	case <-saturated.Ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("saturated circuit was not torn down")
	}
	if conn.circuits.Get(saturated.ID) != nil {
		t.Fatal("saturated circuit remained registered")
	}
	if conn.circuits.Get(healthy.ID) != healthy {
		t.Fatal("unrelated circuit was removed")
	}
}

func TestLinkReadErrorClosesSocketAndOwnedCircuits(t *testing.T) {
	local, peer := net.Pipe()
	conn := newTestConn(t)
	conn.socket = local
	circuit := manualCircuit(conn, 0x80000031, 4)
	conn.circuits.Add(circuit.ID, circuit)
	go conn.readLoop()

	_ = peer.Close()
	select {
	case <-circuit.Ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("circuit survived link failure")
	}
	if conn.ctx.Err() == nil {
		t.Fatal("connection context survived link failure")
	}
	deadline := time.Now().Add(time.Second)
	for conn.circuits.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if conn.circuits.Len() != 0 {
		t.Fatal("registry survived link failure")
	}
	if err := local.SetDeadline(time.Now()); err == nil {
		if _, err := local.Write([]byte{0}); err == nil {
			t.Fatal("socket survived link failure")
		}
	}
}

func testExtendCircuit(t *testing.T, conn *Conn, id uint32) (*Circuit, handshakes.Handshake, []lspec.Lspec) {
	t.Helper()
	circuit := manualCircuit(conn, id, 8)
	back, err := cryptopkg.NewRunningValues(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	forward, err := cryptopkg.NewRunningValues(bytes.Repeat([]byte{3}, 16), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	hop := hops.NewHop(circuit.Ctx, relay.NewDataCellCoder(back, forward), window.NewWindow(1000, 100), window.NewWindow(1000, 100))
	circuit.hops.Append(hop)
	conn.circuits.Add(circuit.ID, circuit)

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := newNTorHandshake(&common.RouterStatus{NodeID: [20]byte{1}, NTorOnionKey: key.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	return circuit, hs, []lspec.Lspec{lspec.NewNodeID([20]byte{1})}
}

func TestExtendTimeoutAndCancellationTearDown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{name: "silent EXTENDED2 deadline"},
		{name: "caller cancellation", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newTestConn(t)
			destroys := make(chan testDestroy, 8)
			serveFast(t, conn, true, destroys)
			circuit, handshake, specs := testExtendCircuit(t, conn, 0x80000041)

			var ctx context.Context
			var cancel context.CancelFunc
			if tc.cancel {
				ctx, cancel = context.WithCancel(context.Background())
				time.AfterFunc(20*time.Millisecond, cancel)
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}
			defer cancel()

			if err := circuit.ExtendContext(ctx, specs, handshakes.HTYPE_NTOR, handshake); err == nil {
				t.Fatal("silent EXTENDED2 did not fail")
			}
			select {
			case got := <-destroys:
				want := uint8(cells.DESTROY_REASON_TIMEOUT)
				if tc.cancel {
					want = cells.DESTROY_REASON_REQUESTED
				}
				if got.id != circuit.ID || got.reason != want {
					t.Fatalf("DESTROY = %#v, want reason %d", got, want)
				}
			case <-time.After(time.Second):
				t.Fatal("extend failure did not emit DESTROY")
			}
			if conn.circuits.Get(circuit.ID) != nil {
				t.Fatal("extend failure left the circuit registered")
			}
		})
	}
}

func TestStreamBeginDeadlineAndCancellationReleaseStream(t *testing.T) {
	conn := newTestConn(t)

	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{name: "silent CONNECTED deadline"},
		{name: "caller cancellation", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			circuit := manualCircuit(conn, 0x80000051, 8)
			circuit.hops.Hops = make([]*hops.Hop, 1)

			var ctx context.Context
			var cancel context.CancelFunc
			if tc.cancel {
				ctx, cancel = context.WithCancel(context.Background())
				time.AfterFunc(20*time.Millisecond, cancel)
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}
			defer cancel()

			if _, err := circuit.NewStreamContext(ctx, "example.com:80", 0); err == nil {
				t.Fatal("silent CONNECTED did not fail")
			}
			if circuit.streams.Len() != 0 {
				t.Fatal("failed begin left a stream registered")
			}
		})
	}
}

func TestCompletedDialIsNotOwnedByCallerContext(t *testing.T) {
	conn := newTestConn(t)
	circuit := manualCircuit(conn, 0x80000061, 8)
	circuit.hops.Hops = make([]*hops.Hop, 1)
	go func() {
		out := <-circuit.WriteRelayCell
		id := out.Cell.GetStreamID()
		if stream := circuit.streams.Get(id); stream != nil {
			stream.InboundControl <- &relay.ConnectedCell{StreamID: id}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	dialed, err := circuit.DialContext(ctx, "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)

	if circuit.streams.Len() != 1 {
		t.Fatal("completed Dial was closed by the caller's context")
	}
	if stream := circuit.streams.Get(1); stream == nil || stream.Ctx.Err() != nil {
		t.Fatal("completed stream was canceled")
	}
	_ = dialed.Close()
}
