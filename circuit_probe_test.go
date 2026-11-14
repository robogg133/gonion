package gonion

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/internal/window"
	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
	cryptopkg "github.com/robogg133/gonion/pkg/crypto"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

// probeHarness is a one-hop circuit with known relay keys and no network I/O.
// The test plays the exit: it decodes the probe BEGIN that the circuit writes
// and seals the reply with the hop's backward keys, so the real read loop and
// relay decoder are exercised.
type probeHarness struct {
	t       *testing.T
	circuit *Circuit
	writes  chan cellWrite
	// forward mirrors the hop's forward running state so the test can decode
	// exactly one outgoing relay cell per probe.
	forward *cryptopkg.RunningValues
	// exit encrypts responses the way the exit hop would.
	exit *relay.RelayCellCoder
	stop context.CancelCauseFunc
}

type probeResult struct {
	result capi.PathBiasProbeResult
	err    error
}

func newProbeHarness(t *testing.T) *probeHarness {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	writeCall := make(chan cellWrite, 8)
	c := &Circuit{
		conn:           &Conn{writeCall: writeCall, ctx: ctx, ctxCancel: cancel},
		Coder:          cells.NewCellCoder(cells.AllKnownCells),
		Ctx:            ctx,
		ctxCancel:      cancel,
		Inbound:        make(chan []byte, 8),
		WriteRelayCell: make(chan RelayOut, 8),
		writeControl:   make(chan RelayOut, 8),
		streams:        &streams{streams: make(map[uint16]*Stream)},
		nextStreamID:   1,
	}

	kf := bytes.Repeat([]byte{0x11}, 16)
	df := bytes.Repeat([]byte{0x22}, 20)
	kb := bytes.Repeat([]byte{0x33}, 16)
	db := bytes.Repeat([]byte{0x44}, 20)
	mk := func(key, seed []byte) *cryptopkg.RunningValues {
		rv, err := cryptopkg.NewRunningValues(key, seed)
		if err != nil {
			t.Fatalf("running values: %v", err)
		}
		return rv
	}
	// The circuit's hop decrypts replies with the backward keys; the test exit
	// coder encrypts with an identically seeded forward state.
	c.hops.Hops = []*hops.Hop{
		hops.NewHop(ctx, relay.NewDataCellCoder(mk(kb, db), mk(kf, df)), window.NewWindow(500, 50), window.NewWindow(500, 50)),
	}
	c.established.Store(true)

	h := &probeHarness{
		t:       t,
		circuit: c,
		writes:  writeCall,
		forward: mk(kf, df),
		exit:    relay.NewDataCellCoder(nil, mk(kb, db)),
		stop:    cancel,
	}
	go c.readloop()
	t.Cleanup(func() {
		cancel(net.ErrClosed)
		pathBiasProbes.Range(func(key, _ any) bool {
			if typed, ok := key.(pathBiasProbeKey); ok && typed.circuit == c {
				t.Errorf("probe state for StreamID %d survived the test", typed.streamID)
			}
			return true
		})
	})
	return h
}

func (h *probeHarness) runProbe(ctx context.Context) <-chan probeResult {
	out := make(chan probeResult, 1)
	go func() {
		result, err := h.circuit.PathBiasProbe(ctx)
		out <- probeResult{result: result, err: err}
	}()
	return out
}

func (h *probeHarness) wait(t *testing.T, out <-chan probeResult) probeResult {
	t.Helper()
	select {
	case result := <-out:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("PathBiasProbe did not return")
		return probeResult{}
	}
}

type probeBegin struct {
	streamID uint16
	target   string
	nonce    [3]byte
}

// nextBegin consumes the link write for a probe BEGIN and returns its
// destination and reserved StreamID.
func (h *probeHarness) nextBegin(t *testing.T) probeBegin {
	t.Helper()
	var write cellWrite
	select {
	case write = <-h.writes:
	case <-time.After(3 * time.Second):
		t.Fatal("probe BEGIN was not written to the link")
	}
	// Acknowledge the link write the way the connection write loop would.
	write.done <- nil

	cell, err := h.circuit.Coder.ReadCell(bytes.NewReader(write.data))
	if err != nil {
		t.Fatalf("decode probe link cell: %v", err)
	}
	relayCell, ok := cell.(*cells.RelayCell)
	if !ok {
		t.Fatalf("probe link cell = %T, want RELAY", cell)
	}
	plain := make([]byte, len(relayCell.Body))
	h.forward.XORKeyStream(plain, relayCell.Body)
	if plain[0] != relay.COMMAND_BEGIN {
		t.Fatalf("probe relay command = %d, want BEGIN (%d)", plain[0], relay.COMMAND_BEGIN)
	}
	streamID := binary.BigEndian.Uint16(plain[3:5])
	length := int(binary.BigEndian.Uint16(plain[9:11]))
	if length < 1 || length > len(plain)-11 {
		t.Fatalf("probe BEGIN payload length = %d", length)
	}
	payload := plain[11 : 11+length]
	if payload[len(payload)-1] != 0 {
		t.Fatalf("probe BEGIN address is not NUL-terminated: %v", payload)
	}
	target := string(payload[:len(payload)-1])
	if streamID == 0 {
		t.Fatal("probe used StreamID zero")
	}
	return probeBegin{streamID: streamID, target: target, nonce: parseProbeTarget(t, target)}
}

func parseProbeTarget(t *testing.T, target string) [3]byte {
	t.Helper()
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("probe target %q: %v", target, err)
	}
	if port != "25" {
		t.Fatalf("probe port = %q, want 25 (path-spec 7.2)", port)
	}
	octets := strings.Split(host, ".")
	if len(octets) != 4 || octets[0] != "0" {
		t.Fatalf("probe host = %q, want 0.a.b.c", host)
	}
	var nonce [3]byte
	for i := 1; i < 4; i++ {
		value, err := strconv.ParseUint(octets[i], 10, 8)
		if err != nil {
			t.Fatalf("probe host octet %q: %v", octets[i], err)
		}
		nonce[i-1] = byte(value)
	}
	return nonce
}

func (h *probeHarness) deliver(t *testing.T, cell relay.Cell) {
	t.Helper()
	body, err := h.exit.Marshal(cell)
	if err != nil {
		t.Fatalf("seal probe reply: %v", err)
	}
	frame, err := h.circuit.Coder.MarshalCell(&cells.RelayCell{CircuitID: h.circuit.ID, Body: body})
	if err != nil {
		t.Fatalf("frame probe reply: %v", err)
	}
	select {
	case h.circuit.Inbound <- frame:
	case <-time.After(3 * time.Second):
		t.Fatal("probe reply was not queued")
	}
}

// deliverEnd queues a RELAY_END with the EXITPOLICY echo shape (address + TTL).
func (h *probeHarness) deliverEnd(t *testing.T, streamID uint16, reason uint8, ipv4 [4]byte) {
	t.Helper()
	payload := append([]byte{}, ipv4[:]...)
	payload = append(payload, 0xff, 0xff, 0xff, 0xff)
	h.deliver(t, &relay.RelayEndCell{StreamID: streamID, Reason: reason, Payload: payload})
}

func probeEcho(nonce [3]byte) [4]byte {
	return [4]byte{0, nonce[0], nonce[1], nonce[2]}
}

func assertNoProbeState(t *testing.T, streamID uint16) {
	t.Helper()
	found := false
	pathBiasProbes.Range(func(key, _ any) bool {
		if typed, ok := key.(pathBiasProbeKey); ok && typed.streamID == streamID {
			found = true
			return false
		}
		return true
	})
	if found {
		t.Fatalf("probe state for StreamID %d was not deregistered", streamID)
	}
}

// TestPathBiasProbeMatchedEcho drives path-spec §7.2 end to end: a nonce
// destination 0.a.b.c:25, a never-reused StreamID with no Stream, and a
// nonce-matching REASON_EXITPOLICY RELAY_END counted as a success.
func TestPathBiasProbeMatchedEcho(t *testing.T) {
	h := newProbeHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := h.runProbe(ctx)
	begin := h.nextBegin(t)
	if h.circuit.streams.Get(begin.streamID) != nil {
		t.Fatal("probe reserved a StreamID that has a Stream")
	}

	h.deliverEnd(t, begin.streamID, relay.END_REASON_EXITPOLICY, probeEcho(begin.nonce))
	result := h.wait(t, out)
	if result.result != capi.PathBiasProbeMatched || result.err != nil {
		t.Fatalf("probe result = %v, %v; want matched", result.result, result.err)
	}
	assertNoProbeState(t, begin.streamID)
}

func TestPathBiasProbeWrongNonce(t *testing.T) {
	h := newProbeHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := h.runProbe(ctx)
	begin := h.nextBegin(t)
	echo := probeEcho(begin.nonce)
	echo[1] ^= 0xff // a different exit echoed a different address
	h.deliverEnd(t, begin.streamID, relay.END_REASON_EXITPOLICY, echo)

	result := h.wait(t, out)
	if result.result != capi.PathBiasProbeMismatched || result.err != nil {
		t.Fatalf("probe result = %v, %v; want mismatched without error", result.result, result.err)
	}
	assertNoProbeState(t, begin.streamID)
}

func TestPathBiasProbeWrongReason(t *testing.T) {
	h := newProbeHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := h.runProbe(ctx)
	begin := h.nextBegin(t)
	// A non-EXITPOLICY END never confirms the probe, even with the exact echo.
	h.deliverEnd(t, begin.streamID, relay.END_REASON_DONE, probeEcho(begin.nonce))

	result := h.wait(t, out)
	if result.result != capi.PathBiasProbeMismatched || result.err != nil {
		t.Fatalf("probe result = %v, %v; want mismatched without error", result.result, result.err)
	}
}

func TestPathBiasProbeUnexpectedCell(t *testing.T) {
	h := newProbeHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := h.runProbe(ctx)
	begin := h.nextBegin(t)
	// path-spec §7.2: unrecognized relay cells after the probe are a failure.
	h.deliver(t, &relay.DataCell{StreamID: begin.streamID, Payload: []byte("unexpected")})

	result := h.wait(t, out)
	if result.result != capi.PathBiasProbeMismatched || result.err != nil {
		t.Fatalf("probe result = %v, %v; want mismatched without error", result.result, result.err)
	}
}

func TestPathBiasProbeCancellation(t *testing.T) {
	h := newProbeHarness(t)
	ctx, cancel := context.WithCancel(context.Background())

	out := h.runProbe(ctx)
	begin := h.nextBegin(t)
	cancel()

	result := h.wait(t, out)
	if result.result != capi.PathBiasProbeMismatched {
		t.Fatalf("probe result = %v, want mismatched after a sent probe", result.result)
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("probe error = %v, want context.Canceled", result.err)
	}
	assertNoProbeState(t, begin.streamID)
}

func TestPathBiasProbeDeadline(t *testing.T) {
	h := newProbeHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out := h.runProbe(ctx)
	begin := h.nextBegin(t)

	result := h.wait(t, out)
	if result.result != capi.PathBiasProbeMismatched {
		t.Fatalf("probe result = %v, want mismatched after the deadline", result.result)
	}
	if !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("probe error = %v, want context.DeadlineExceeded", result.err)
	}
	assertNoProbeState(t, begin.streamID)
}

func TestPathBiasProbeCanceledBeforeSend(t *testing.T) {
	h := newProbeHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := h.circuit.PathBiasProbe(ctx)
	if result != capi.PathBiasProbeUnsent {
		t.Fatalf("probe result = %v, want unsent", result)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("probe error = %v, want context.Canceled", err)
	}
	select {
	case write := <-h.writes:
		t.Fatalf("canceled probe wrote a cell: %x", write.data)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPathBiasProbeDeadCircuit(t *testing.T) {
	h := newProbeHarness(t)
	h.stop(net.ErrClosed)

	result, err := h.circuit.PathBiasProbe(context.Background())
	if result != capi.PathBiasProbeUnsent {
		t.Fatalf("probe result = %v, want unsent", result)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("probe error = %v, want net.ErrClosed", err)
	}
	select {
	case write := <-h.writes:
		t.Fatalf("dead circuit wrote a probe cell: %x", write.data)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPathBiasProbeRequiresBuiltCircuit(t *testing.T) {
	h := newProbeHarness(t)
	h.circuit.established.Store(false)

	result, err := h.circuit.PathBiasProbe(context.Background())
	if result != capi.PathBiasProbeUnsent {
		t.Fatalf("probe result = %v, want unsent", result)
	}
	if !errors.Is(err, ErrCircuit) {
		t.Fatalf("probe error = %v, want ErrCircuit", err)
	}
}

func TestPathBiasProbeTargetAndNonce(t *testing.T) {
	// C tor_dup_ip of the masked uint32 prints 0.<bits16-23>.<bits8-15>.<bits0-7>.
	if got := pathBiasProbeTarget(0x00a1b2c3); got != "0.161.178.195:25" {
		t.Fatalf("target = %q, want 0.161.178.195:25", got)
	}
	for i := 0; i < 64; i++ {
		nonce, err := newPathBiasProbeNonce()
		if err != nil {
			t.Fatalf("nonce: %v", err)
		}
		if nonce&^pathBiasProbeNonceMask != 0 {
			t.Fatalf("nonce %#x is not 24-bit", nonce)
		}
		if target := pathBiasProbeTarget(nonce); !strings.HasPrefix(target, "0.") {
			t.Fatalf("target %q does not start with 0.", target)
		}
	}
}

func TestPathBiasProbeStreamIDIsNeverReused(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(net.ErrClosed) })
	c := &Circuit{
		Ctx:          ctx,
		ctxCancel:    cancel,
		streams:      &streams{streams: make(map[uint16]*Stream)},
		nextStreamID: 1,
	}

	probeID, err := c.reservePathBiasProbeStreamID()
	if err != nil {
		t.Fatalf("probe StreamID: %v", err)
	}
	if probeID == 0 {
		t.Fatal("probe StreamID zero")
	}
	stream, err := c.reserveStream("example.com:80", 0)
	if err != nil {
		t.Fatalf("reserveStream: %v", err)
	}
	if stream.ID == probeID {
		t.Fatalf("a Stream reused the probe StreamID %d", probeID)
	}
	_ = stream.Free()

	c.streamMu.Lock()
	c.nextStreamID = 65535
	c.streamMu.Unlock()
	last, err := c.reservePathBiasProbeStreamID()
	if err != nil || last != 65535 {
		t.Fatalf("last StreamID = %d, %v; want 65535", last, err)
	}
	if _, err := c.reservePathBiasProbeStreamID(); err == nil {
		t.Fatal("exhausted circuit still reserved a probe StreamID")
	}
}

// rememberStreamFailure keeps only the most recent failed stream attempt's
// END reason, and a zero reason never overwrites or creates a record.
func TestPathBiasProbeRecordsStreamFailureReason(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(net.ErrClosed) })
	c := &Circuit{
		Ctx:          ctx,
		ctxCancel:    cancel,
		streams:      &streams{streams: make(map[uint16]*Stream)},
		nextStreamID: 1,
	}

	if got := c.StreamFailureReason(); got != 0 {
		t.Fatalf("fresh circuit recorded stream failure reason %d", got)
	}
	c.rememberStreamFailure(relay.END_REASON_TORPROTOCOL)
	if got := c.StreamFailureReason(); got != relay.END_REASON_TORPROTOCOL {
		t.Fatalf("StreamFailureReason = %d, want TORPROTOCOL (%d)", got, relay.END_REASON_TORPROTOCOL)
	}
	c.rememberStreamFailure(relay.END_REASON_EXITPOLICY)
	if got := c.StreamFailureReason(); got != relay.END_REASON_EXITPOLICY {
		t.Fatalf("StreamFailureReason = %d, want the most recent failed attempt EXITPOLICY (%d)", got, relay.END_REASON_EXITPOLICY)
	}
	c.rememberStreamFailure(0)
	if got := c.StreamFailureReason(); got != relay.END_REASON_EXITPOLICY {
		t.Fatal("a zero reason overwrote the recorded failure")
	}
}

// A caller context without a deadline gets the documented default bound; a
// caller deadline is passed through unchanged and stays authoritative.
func TestPathBiasProbeDefaultDeadline(t *testing.T) {
	ctx, cancel := pathBiasProbeContext(context.Background())
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("no default deadline was applied")
	}
	remaining := time.Until(dl)
	if remaining > pathBiasProbeDefaultTimeout || remaining < pathBiasProbeDefaultTimeout-2*time.Second {
		t.Fatalf("default deadline = %v, want about %v", remaining, pathBiasProbeDefaultTimeout)
	}

	caller, cancelCaller := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCaller()
	got, cancelGot := pathBiasProbeContext(caller)
	defer cancelGot()
	callerDeadline, ok := caller.Deadline()
	if !ok {
		t.Fatal("caller deadline disappeared")
	}
	if gotDeadline, ok := got.Deadline(); !ok || !gotDeadline.Equal(callerDeadline) {
		t.Fatalf("caller deadline %v was replaced by %v", callerDeadline, gotDeadline)
	}
}

// A relay writer stuck while holding the marshal lock cannot defeat the
// probe's bounded wait: the send gives up at the deadline and reports the
// probe as unsent, without writing a cell.
func TestPathBiasProbeRelayLockBound(t *testing.T) {
	h := newProbeHarness(t)
	h.circuit.relayMu.Lock()
	defer h.circuit.relayMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	result, err := h.circuit.PathBiasProbe(ctx)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("probe returned after %v, not bounded by the deadline", elapsed)
	}
	if result != capi.PathBiasProbeUnsent {
		t.Fatalf("probe result = %v, want unsent", result)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe error = %v, want context.DeadlineExceeded", err)
	}
	select {
	case write := <-h.writes:
		t.Fatalf("stuck-lock probe wrote a cell: %x", write.data)
	case <-time.After(50 * time.Millisecond):
	}
}
