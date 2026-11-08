package gonion

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/internal/window"
	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/crypto"
	"github.com/robogg133/gonion/pkg/handshakes"
	"github.com/robogg133/gonion/pkg/lspec"
)

const (
	// CIRCUIT_BUILD_TIMEOUT bounds source-compatible NewCircuit/NewFastCircuit
	// and Extend wrappers that have no caller context.
	CIRCUIT_BUILD_TIMEOUT = 60 * time.Second
	// STREAM_BEGIN_TIMEOUT bounds BEGIN/BEGIN_DIR/CONNECTED setup for the
	// context-free NewStream and Dial wrappers.
	STREAM_BEGIN_TIMEOUT = 30 * time.Second

	// MaxCircuitsPerConn is the per-OR-connection circuit ceiling. It keeps
	// registry and goroutine counts proportional to one link's resources.
	MaxCircuitsPerConn = 1024
	// MaxStreamsPerCircuit is the per-circuit stream ceiling. Stream IDs are
	// never reused, so this also bounds live stream state for one circuit.
	MaxStreamsPerCircuit = 4096

	// queued cell ceilings. Each link cell is at most CELL_BODY_LEN plus a
	// five-byte header; the byte values below are the resulting hard bounds.
	maxQueuedLinkCells      = 4096
	maxCircuitInboundCells  = 1024
	maxCircuitOutboundCells = 512
	maxCircuitControlCells  = 32
	maxStreamOutboundCells  = 32
	maxStreamControlCells   = 16

	MaxQueuedLinkBytes      = maxQueuedLinkCells * (cells.CELL_BODY_LEN + 5)
	MaxCircuitInboundBytes  = maxCircuitInboundCells * (cells.CELL_BODY_LEN + 5)
	MaxCircuitOutboundBytes = maxCircuitOutboundCells * (cells.CELL_BODY_LEN + 5)
	MaxCircuitControlBytes  = maxCircuitControlCells * (cells.CELL_BODY_LEN + 5)
)

// CircuitIDExhaustedError reports that every bounded random CircID attempt
// collided, was zero, or was already reserved. The existing circuits are left
// untouched.
type CircuitIDExhaustedError struct{ Attempts int }

func (e *CircuitIDExhaustedError) Error() string {
	return fmt.Sprintf("gonion: circuit id allocation exhausted after %d attempts", e.Attempts)
}

func (e *CircuitIDExhaustedError) Unwrap() error { return ErrCircuit }

// CircuitLimitError reports the per-connection circuit ceiling.
type CircuitLimitError struct{ Limit int }

func (e *CircuitLimitError) Error() string {
	return fmt.Sprintf("gonion: circuit limit reached (%d)", e.Limit)
}

func (e *CircuitLimitError) Unwrap() error { return ErrCircuit }

// StreamLimitError reports the per-circuit stream ceiling.
type StreamLimitError struct{ Limit int }

func (e *StreamLimitError) Error() string {
	return fmt.Sprintf("gonion: circuit stream limit reached (%d)", e.Limit)
}

func (e *StreamLimitError) Unwrap() error { return ErrStream }

type Circuit struct {
	conn *Conn

	ID uint32

	isUp bool

	hops hops.Chain

	SendMeVersion uint8

	streams       *streams
	nextStreamID  uint32
	streamMu      sync.Mutex
	usedStreamIDs [65536 / 8]byte
	maxStreams    int

	Coder *cells.CellCoder

	WriteRelayCell chan RelayOut
	writeControl   chan RelayOut
	Inbound        chan []byte
	inboundBytes   atomic.Int64
	Ctx            context.Context
	ctxCancel      context.CancelCauseFunc
	rawCancel      context.CancelCauseFunc
	established    atomic.Bool
	closeOnce      sync.Once
	relayMu        sync.Mutex
	controlMu      sync.RWMutex
	extendMu       sync.Mutex
	extensions     int
	lastKH         []byte // final physical hop nonce, protected by extendMu
	e2e            bool
	intro          bool
	service        *serviceCircuitState // protected by controlMu

	extended2Received chan *relay.Extended2Cell

	// HSControl receives circuit-level hidden-service control cells
	// (RENDEZVOUS_ESTABLISHED, RENDEZVOUS2, INTRO_ESTABLISHED, INTRODUCE_ACK
	// that arrive with StreamID == 0). nil until a hidden-service op registers
	// a handler by assigning a buffered channel.
	HSControl chan relay.Cell
}

type RelayOut struct {
	Cell relay.Cell
	Dst  int
	sent chan error // optional, buffered acknowledgement after the link write
}

// newCircuitContext allocates and registers a circuit before any wire traffic.
// The returned stop function must be called after the handshake so a completed
// build is not owned by the caller's build context.
func (c *Conn) newCircuitContext(ctx context.Context, kind string) (*Circuit, func() bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := c.ctx.Err(); err != nil {
		return nil, nil, context.Cause(c.ctx)
	}
	id, err := c.allocCircID()
	if err != nil {
		return nil, nil, err
	}
	baseLog := logger(c.ctx).With().
		Str("component", "circuit").
		Uint32("circ_id", id).
		Str("kind", kind).
		Logger()
	circuitCtx, cancel := context.WithCancelCause(withLogger(c.ctx, baseLog))
	circuit := &Circuit{
		conn:              c,
		ID:                id,
		Inbound:           make(chan []byte, maxCircuitInboundCells),
		WriteRelayCell:    make(chan RelayOut, maxCircuitOutboundCells),
		writeControl:      make(chan RelayOut, maxCircuitControlCells),
		Ctx:               circuitCtx,
		rawCancel:         cancel,
		extended2Received: make(chan *relay.Extended2Cell, 1),
		streams: &streams{
			streams: make(map[uint16]*Stream),
		},
		SendMeVersion: 1,
		nextStreamID:  1,
		Coder:         cells.NewCellCoder(cells.AllKnownCells),
	}
	// Any caller that cancels circuit ownership goes through the same teardown
	// path, including code paths outside the circuit loops.
	circuit.ctxCancel = func(cause error) {
		circuit.teardown(cause, destroyReasonFor(cause), true)
	}
	if err := c.registerCircuit(circuit); err != nil {
		cancel(err)
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { cancel(context.Cause(ctx)) })
	return circuit, stop, nil
}

// NewCircuit preserves the historical signature. The id argument is retained
// for source compatibility but is no longer an allocator: Conn draws a random,
// nonzero, collision-checked CircID for the negotiated link version.
func (c *Conn) NewCircuit(id uint32, htype uint16, hs handshakes.Handshake) (*Circuit, error) {
	_ = id
	ctx, cancel := context.WithTimeout(c.ctx, CIRCUIT_BUILD_TIMEOUT)
	defer cancel()
	return c.NewCircuitContext(ctx, htype, hs)
}

// NewCircuitContext builds a CREATE2 circuit. Cancellation or deadline expiry
// tears the circuit down, including a best-effort client DESTROY once the
// circuit was established.
func (c *Conn) NewCircuitContext(ctx context.Context, htype uint16, hs handshakes.Handshake) (circuit *Circuit, err error) {
	circuit, stop, err := c.newCircuitContext(ctx, "create2")
	if err != nil {
		return nil, err
	}
	built := circuit
	defer stop()
	success := false
	defer func() {
		if !success {
			built.teardown(err, destroyReasonFor(err), true)
		}
	}()
	log := logger(circuit.Ctx)
	log.Info().Uint16("handshake", htype).Msg("creating circuit")

	create2 := cells.Create2Cell{
		CircuitID:     circuit.ID,
		HandshakeType: htype,
		Handshake:     hs,
	}
	if err := circuit.SendCell(&create2); err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "send CREATE2 failed", err)
	}

	var rawCell []byte
	select {
	case rawCell = <-circuit.Inbound:
		circuit.releaseInbound(len(rawCell))
	case <-circuit.Ctx.Done():
		return nil, circuitWaitError(circuit.Ctx, "circuit closed while waiting CREATED2")
	}

	cell, err := circuit.Coder.ReadCell(bytes.NewReader(rawCell))
	if err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "decode CREATED2 failed", err)
	}
	if cell.ID() != cells.COMMAND_CREATED2 {
		log.Error().Uint8("cmd", cell.ID()).Type("cell_type", cell.ID()).Msg("expected CREATED2")
		return nil, Publicf(ErrProtocolViolation, "expected CREATED2, got command %d", cell.ID())
	}

	created2, ok := cell.(*cells.Created2Cell)
	if !ok {
		return nil, Public(ErrProtocolViolation, "malformed CREATED2 cell")
	}
	if err := created2.DecodeHandshake(htype); err != nil {
		return nil, fail(circuit.Ctx, ErrHandshake, "decode CREATED2 handshake failed", err)
	}

	keys := &crypto.CircuitKeys{}
	switch htype {
	case handshakes.HTYPE_NTOR:
		nths, ok := hs.(*handshakes.Client_NTorHandshake)
		if !ok || nths == nil {
			return nil, Public(ErrHandshake, "invalid ntor client handshake")
		}
		server, ok := created2.Handshake.(*handshakes.Server_NTorHandshake)
		if !ok || server == nil {
			return nil, Public(ErrHandshake, "invalid ntor server handshake")
		}
		keys, err = nths.Derive(server, nths.KeyID)
		if err != nil {
			return nil, fail(circuit.Ctx, ErrHandshake, "ntor derive failed", err)
		}
	default:
		return nil, Publicf(ErrHandshake, "unsupported handshake type %d", htype)
	}

	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)

	back, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "init hop crypto failed", err)
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "init hop crypto failed", err)
	}

	hop := hops.NewHop(circuit.Ctx, relay.NewDataCellCoder(back, forwards), rcvWindow, sndWindow)
	circuit.hops.Append(hop)
	go circuit.sendmeManage(0, hop)
	circuit.lastKH = bytes.Clone(keys.KH)
	circuit.isUp = true
	circuit.established.Store(true)
	go circuit.writeLoop()
	go circuit.readloop()
	success = true
	log.Info().Int("hops", circuit.hops.Len()).Msg("circuit created")
	return circuit, nil
}

// NewFastCircuit preserves the historical signature. The id argument is
// retained for source compatibility but Conn owns allocation.
func (c *Conn) NewFastCircuit(id uint32) (*Circuit, error) {
	_ = id
	ctx, cancel := context.WithTimeout(c.ctx, CIRCUIT_BUILD_TIMEOUT)
	defer cancel()
	return c.NewFastCircuitContext(ctx)
}

// NewFastCircuitContext builds a one-hop CREATE_FAST circuit. Cancellation or
// deadline expiry tears the circuit down and removes its registry entry.
func (c *Conn) NewFastCircuitContext(ctx context.Context) (circuit *Circuit, err error) {
	circuit, stop, err := c.newCircuitContext(ctx, "create_fast")
	if err != nil {
		return nil, err
	}
	built := circuit
	defer stop()
	success := false
	defer func() {
		if !success {
			built.teardown(err, destroyReasonFor(err), true)
		}
	}()
	circuit.SendMeVersion = 0

	xMaterial := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, xMaterial); err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "generate CREATE_FAST material failed", err)
	}

	log := logger(circuit.Ctx)
	log.Info().Msg("creating fast circuit")

	createFast := cells.CreateFastCell{
		CircuitID: circuit.ID,
		X:         [20]byte(xMaterial),
	}
	if err := circuit.SendCell(&createFast); err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "send CREATE_FAST failed", err)
	}

	var rawCell []byte
	select {
	case rawCell = <-circuit.Inbound:
		circuit.releaseInbound(len(rawCell))
	case <-circuit.Ctx.Done():
		return nil, circuitWaitError(circuit.Ctx, "circuit closed while waiting CREATED_FAST")
	}
	cell, err := circuit.Coder.ReadCell(bytes.NewReader(rawCell))
	if err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "decode CREATED_FAST failed", err)
	}
	if cell.ID() != cells.COMMAND_CREATED_FAST {
		log.Error().Uint8("cmd", cell.ID()).Msg("expected CREATED_FAST")
		return nil, Publicf(ErrProtocolViolation, "expected CREATED_FAST, got command %d", cell.ID())
	}

	createdFast, ok := cell.(*cells.CreatedFastCell)
	if !ok {
		return nil, Public(ErrProtocolViolation, "malformed CREATED_FAST cell")
	}
	keys, err := crypto.DeriveKeysCreateFast([20]byte(xMaterial), createdFast.Y)
	if err != nil {
		return nil, fail(circuit.Ctx, ErrHandshake, "CREATE_FAST key derive failed", err)
	}
	if !bytes.Equal(keys.KH, createdFast.KH[:]) {
		log.Error().Msg("CREATE_FAST KH mismatch")
		return nil, Public(ErrHandshake, "CREATE_FAST key confirmation failed")
	}

	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)
	back, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "init hop crypto failed", err)
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return nil, fail(circuit.Ctx, ErrCircuit, "init hop crypto failed", err)
	}

	hop := hops.NewHop(circuit.Ctx, relay.NewDataCellCoder(back, forwards), rcvWindow, sndWindow)
	circuit.hops.Append(hop)
	go circuit.sendmeManage(0, hop)
	circuit.isUp = true
	circuit.established.Store(true)
	go circuit.readloop()
	go circuit.writeLoop()
	success = true
	log.Info().Int("hops", circuit.hops.Len()).Msg("fast circuit created")
	return circuit, nil
}

// circuitWaitError converts a canceled handshake wait into a typed public error
// so teardown can select the matching DESTROY reason.
func circuitWaitError(ctx context.Context, msg string) error {
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return Public(ErrTimeout, msg+": deadline exceeded")
	case errors.Is(cause, ErrClosed):
		return Public(ErrClosed, msg)
	case cause != nil:
		return fail(ctx, ErrCircuit, msg, cause)
	default:
		return Public(ErrCircuit, msg)
	}
}

// destroyReasonFor maps an internal terminal cause to a tor-spec DESTROY reason.
func destroyReasonFor(cause error) uint8 {
	var limit *CircuitLimitError
	switch {
	case cause == nil:
		return cells.DESTROY_REASON_NONE
	case errors.Is(cause, context.DeadlineExceeded), errors.Is(cause, ErrTimeout):
		return cells.DESTROY_REASON_TIMEOUT
	case errors.Is(cause, context.Canceled):
		return cells.DESTROY_REASON_REQUESTED
	case errors.Is(cause, ErrProtocolViolation):
		return cells.DESTROY_REASON_PROTCOL
	case errors.Is(cause, ErrClosed):
		return cells.DESTROY_REASON_NONE
	case errors.As(cause, &limit):
		return cells.DESTROY_REASON_RESOURCELIMIT
	default:
		return cells.DESTROY_REASON_INTERNAL
	}
}

// Extend preserves the context-free API with a bounded default deadline.
func (c *Circuit) Extend(lspecs []lspec.Lspec, htype uint16, handshake handshakes.Handshake) error {
	ctx, cancel := context.WithTimeout(c.Ctx, CIRCUIT_BUILD_TIMEOUT)
	defer cancel()
	return c.ExtendContext(ctx, lspecs, htype, handshake)
}

// ExtendContext extends the circuit and runs the same idempotent teardown on
// every failure that leaves the extension attempt in flight. Preflight refusal
// before any cell is sent leaves the existing circuit usable.
func (c *Circuit) ExtendContext(ctx context.Context, lspecs []lspec.Lspec, htype uint16, handshake handshakes.Handshake) (err error) {
	if ctx == nil {
		ctx = c.Ctx
	}
	c.extendMu.Lock()
	defer c.extendMu.Unlock()
	if c.Ctx.Err() != nil {
		return context.Cause(c.Ctx)
	}
	if c.e2e {
		return Public(ErrExtend, "cannot extend a rendezvous circuit")
	}
	if c.extensions >= 8 {
		return Public(ErrExtend, "RELAY_EARLY limit exhausted")
	}
	nths, ok := handshake.(*handshakes.Client_NTorHandshake)
	if htype != handshakes.HTYPE_NTOR || !ok || nths == nil {
		return Public(ErrHandshake, "unsupported extension handshake")
	}
	log := logger(c.Ctx)
	if c.hops.Len() == 0 {
		return Public(ErrExtend, "cannot extend empty circuit")
	}
	if err := ctx.Err(); err != nil {
		c.teardown(err, destroyReasonFor(err), true)
		return err
	}
	stop := context.AfterFunc(ctx, func() {
		cause := context.Cause(ctx)
		c.teardown(cause, destroyReasonFor(cause), true)
	})
	defer stop()

	from := c.hops.Len()
	log.Info().Int("from_hops", from).Uint16("handshake", htype).Msg("extending circuit")

	extend2 := &relay.Extend2Cell{
		StreamID:  0,
		Lspecs:    lspecs,
		HType:     htype,
		Handshake: handshake,
	}

	dst := c.hops.Len() - 1
	c.extensions++
	if err := c.sendRelayContext(ctx, extend2, dst, true); err != nil {
		reasonCause := err
		if ctx.Err() != nil {
			reasonCause = context.Cause(ctx)
		}
		c.teardown(err, destroyReasonFor(reasonCause), true)
		return fail(c.Ctx, ErrExtend, "send EXTEND2 failed", err)
	}

	var extended *relay.Extended2Cell
	select {
	case extended = <-c.extended2Received:
	case <-c.Ctx.Done():
		cause := context.Cause(c.Ctx)
		c.teardown(cause, destroyReasonFor(cause), true)
		return circuitWaitError(c.Ctx, "circuit closed while waiting EXTENDED2")
	case <-ctx.Done():
		cause := context.Cause(ctx)
		err := circuitWaitError(ctx, "circuit extension timed out")
		c.teardown(err, destroyReasonFor(cause), true)
		return err
	}
	if extended == nil {
		err := Public(ErrExtend, "empty EXTENDED2")
		c.teardown(err, destroyReasonFor(err), true)
		return err
	}
	if err := extended.DecodeHandshake(htype); err != nil {
		c.teardown(err, destroyReasonFor(err), true)
		return fail(c.Ctx, ErrHandshake, "decode EXTENDED2 handshake failed", err)
	}

	keys := &crypto.CircuitKeys{}
	switch htype {
	case handshakes.HTYPE_NTOR:
		server, ok := extended.Handshake.(*handshakes.Server_NTorHandshake)
		if !ok || server == nil {
			err := Public(ErrHandshake, "invalid ntor server handshake")
			c.teardown(err, destroyReasonFor(err), true)
			return err
		}
		keys, err = nths.Derive(server, nths.KeyID)
		if err != nil {
			c.teardown(err, destroyReasonFor(err), true)
			return fail(c.Ctx, ErrHandshake, "ntor derive on extend failed", err)
		}
	default:
		err := Publicf(ErrHandshake, "unsupported handshake type %d", htype)
		c.teardown(err, destroyReasonFor(err), true)
		return err
	}

	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)

	backwards, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		c.teardown(err, destroyReasonFor(err), true)
		return fail(c.Ctx, ErrExtend, "init hop crypto failed", err)
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		c.teardown(err, destroyReasonFor(err), true)
		return fail(c.Ctx, ErrExtend, "init hop crypto failed", err)
	}

	if err := ctx.Err(); err != nil {
		c.teardown(err, destroyReasonFor(err), true)
		return err
	}
	c.lastKH = bytes.Clone(keys.KH)
	hop := hops.NewHop(c.Ctx, relay.NewDataCellCoder(backwards, forwards), rcvWindow, sndWindow)
	c.hops.Append(hop)
	go c.sendmeManage(c.hops.Len()-1, hop)
	stop()
	log.Info().Int("hops", c.hops.Len()).Msg("circuit extended")
	return nil
}

func (c *Circuit) HopCount() int {
	return c.hops.Len()
}

// AppendE2EHop attaches an end-to-end (hidden-service) hop as the last hop of
// the circuit. Unlike Extend/ExtendTo it does NOT send an EXTEND2: the crypto
// keys are computed locally from the already-established rendezvous key seed
// (rend-spec-v3 §JOIN_REND). Kf/Kb are AES-256-CTR keys; Df/Db seed SHA3-256.
// The virtual hop owns independent flow-control and digest state.
func (c *Circuit) AppendE2EHop(Kf, Kb, Df, Db []byte) error {
	c.extendMu.Lock()
	defer c.extendMu.Unlock()
	return c.appendE2EHop(Kf, Kb, Df, Db)
}

func (c *Circuit) appendE2EHop(Kf, Kb, Df, Db []byte) error {
	if c.e2e {
		return Public(ErrProtocolViolation, "E2E hop already installed")
	}
	if c.hops.Len() == 0 {
		return Public(ErrExtend, "cannot append e2e hop to empty circuit")
	}
	back, err := crypto.NewHSRunningValues(Kb, Db)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "init e2e hop crypto failed", err)
	}
	forwards, err := crypto.NewHSRunningValues(Kf, Df)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "init e2e hop crypto failed", err)
	}
	hop := hops.NewHop(c.Ctx, relay.NewDataCellCoder(back, forwards), window.NewWindow(1000, 100), window.NewWindow(1000, 100))
	c.hops.Append(hop)
	go c.sendmeManage(c.hops.Len()-1, hop)
	c.e2e = true
	clear(c.lastKH)
	c.lastKH = nil
	logger(c.Ctx).Info().Int("hops", c.hops.Len()).Msg("e2e hop appended")
	return nil
}

// SendHSControl relays a circuit-level hidden-service control cell (StreamID==0)
// through the onion encryption layers to the final hop. The cell is marshalled
// exactly like any other relay cell; the e2e hop (if present) supplies the
// outermost encryption layer.
func (c *Circuit) SendHSControl(cell relay.Cell) error {
	if cell == nil || cell.GetStreamID() != 0 {
		return Public(ErrProtocolViolation, "HS control requires StreamID zero")
	}
	return c.sendRelay(cell, c.hops.Len()-1, false)
}

// Serialize encryption with enqueueing: CTR/digest order must be wire order,
// including EXTEND2 and control cells sent outside the stream write loop.
func (c *Circuit) sendRelay(cell relay.Cell, dst int, early bool) error {
	return c.sendRelayContext(c.Ctx, cell, dst, early)
}

func (c *Circuit) sendRelayContext(ctx context.Context, cell relay.Cell, dst int, early bool) error {
	c.relayMu.Lock()
	defer c.relayMu.Unlock()
	if c.Ctx.Err() != nil {
		return context.Cause(c.Ctx)
	}
	if ctx != nil && ctx.Err() != nil {
		return context.Cause(ctx)
	}
	body, err := c.hops.MarshalMessage(cell, dst)
	if err != nil {
		return err
	}
	if data, ok := cell.(*relay.DataCell); ok {
		hop := c.hops.At(dst)
		hop.Send().SetDigest(data.Digest())
		hop.Send().Subtract(1)
	}
	if early {
		return c.SendCellContext(ctx, &cells.RelayEarlyCell{C: &cells.RelayCell{Body: body}})
	}
	return c.SendCellContext(ctx, &cells.RelayCell{Body: body})
}

// teardown is the single idempotent terminal transition. It cancels circuit
// ownership, optionally best-effort sends DESTROY for an established circuit,
// removes exactly this Circuit from the registry, and releases every stream.
// The registry is deliberately left untouched only for a different Circuit
// value with the same ID.
func (c *Circuit) teardown(cause error, reason uint8, notifyPeer bool) {
	if cause == nil {
		cause = ErrClosed
	}
	c.closeOnce.Do(func() {
		// Remove this exact registry entry before cancellation becomes
		// observable, so a watcher of Ctx.Done cannot still find the circuit.
		if c.conn != nil && c.conn.circuits != nil {
			c.conn.circuits.DeleteIf(c.ID, c)
		}
		if c.rawCancel != nil {
			c.rawCancel(cause)
		} else if c.ctxCancel != nil {
			c.ctxCancel(cause)
		}
		if notifyPeer && c.established.Load() && c.conn != nil {
			c.conn.sendDestroy(c.ID, reason)
		}
	})
	// Streams are closed outside closeOnce so a stream-triggered Circuit.Close
	// cannot re-enter the once body. Stream close is itself idempotent.
	c.closeAllStreams()
}

func (c *Circuit) abort(cause error) {
	c.teardown(cause, destroyReasonFor(cause), true)
}

func (c *Circuit) abortWithReason(cause error, reason uint8) {
	c.teardown(cause, reason, true)
}

func (c *Circuit) closeAllStreams() {
	for _, stream := range c.streams.snapshot() {
		_ = stream.Free()
	}
}

// reserveInbound accounts the wire bytes queued for this circuit. The cell
// count is bounded by the channel capacity; this bounds frames that arrive at
// the maximum variable-cell length as well.
func (c *Circuit) reserveInbound(n int) bool {
	for {
		current := c.inboundBytes.Load()
		next := current + int64(n)
		if next > int64(MaxCircuitInboundBytes) {
			return false
		}
		if c.inboundBytes.CompareAndSwap(current, next) {
			return true
		}
	}
}

func (c *Circuit) releaseInbound(n int) {
	for {
		current := c.inboundBytes.Load()
		next := current - int64(n)
		if next < 0 {
			next = 0
		}
		if c.inboundBytes.CompareAndSwap(current, next) {
			return
		}
	}
}

func (c *Circuit) Close() error {
	logger(c.Ctx).Info().Msg("closing circuit")
	c.teardown(ErrClosed, cells.DESTROY_REASON_NONE, true)
	return nil
}

func (c *Circuit) handleCell(cell cells.Cell) {
	log := logger(c.Ctx)
	switch cell.ID() {
	case cells.COMMAND_DESTROY:
		destroy, ok := cell.(*cells.DestroyCell)
		if !ok {
			c.abort(Public(ErrProtocolViolation, "malformed DESTROY"))
			return
		}
		reasonS := common.DestroyGetReasonS(destroy.Reason)
		log.Warn().Uint8("reason", destroy.Reason).Str("reason_s", reasonS).Msg("DESTROY received")
		// The remote peer initiated teardown; do not echo DESTROY back.
		c.teardown(Publicf(ErrCircuit, "destroyed: %s", reasonS), cells.DESTROY_REASON_NONE, false)
	default:
		log.Debug().Uint8("cmd", cell.ID()).Msg("unhandled link cell on circuit")
	}
}

func (c *Circuit) SendCell(cell cells.Cell) error {
	return c.SendCellContext(c.Ctx, cell)
}

// SendCellContext writes a link cell while honoring both circuit ownership and
// the caller's context/deadline.
func (c *Circuit) SendCellContext(ctx context.Context, cell cells.Cell) error {
	if ctx == nil {
		ctx = c.Ctx
	}
	cell.SetCircuitID(c.ID)

	b, err := c.Coder.MarshalCell(cell)
	if err != nil {
		pub := fail(c.Ctx, ErrIO, "marshal cell failed", err)
		c.abort(pub)
		return pub
	}

	done := make(chan error, 1)
	select {
	case c.conn.writeCall <- cellWrite{data: b, done: done}:
	case <-c.Ctx.Done():
		return circuitWaitError(c.Ctx, "circuit closed before link write")
	case <-ctx.Done():
		return circuitWaitError(ctx, "link write canceled")
	}
	select {
	case err := <-done:
		return err
	case <-c.Ctx.Done():
		return circuitWaitError(c.Ctx, "circuit closed before link write completed")
	case <-ctx.Done():
		return circuitWaitError(ctx, "link write canceled")
	}
}
