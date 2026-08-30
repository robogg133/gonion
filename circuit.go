package gonion

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"sync"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/internal/window"
	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/crypto"
	"github.com/robogg133/gonion/pkg/handshakes"
	"github.com/robogg133/gonion/pkg/lspec"
)

type Circuit struct {
	conn *Conn

	ID uint32

	isUp bool

	hops hops.Chain

	SendMeVersion uint8

	streams      *streams
	nextStreamID uint16

	Coder *cells.CellCoder

	WriteRelayCell chan RelayOut
	Inbound        chan []byte
	Ctx            context.Context
	ctxCancel      context.CancelCauseFunc
	closeOnce      sync.Once

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
}

func (c *Conn) NewCircuit(id uint32, htype uint16, hs handshakes.Handshake) (*Circuit, error) {
	suc := false
	circID := shared.MSB(id)

	baseLog := logger(c.ctx).With().
		Str("component", "circuit").
		Uint32("circ_id", circID).
		Uint16("handshake", htype).
		Str("kind", "create2").
		Logger()
	ctx, cancel := context.WithCancelCause(withLogger(c.ctx, baseLog))

	circuit := &Circuit{
		conn:              c,
		ID:                circID,
		Inbound:           make(chan []byte, 2048),
		WriteRelayCell:    make(chan RelayOut, 512),
		Ctx:               ctx,
		ctxCancel:         cancel,
		extended2Received: make(chan *relay.Extended2Cell, 1),
		streams: &streams{
			streams: make(map[uint16]*Stream),
		},
		SendMeVersion: 1,
		nextStreamID:  1,
		isUp:          true,
		Coder:         cells.NewCellCoder(cells.AllKnownCells),
	}
	c.circuits.Set(circuit.ID, circuit)
	defer func() {
		if !suc {
			c.circuits.Delete(circuit.ID)
			circuit.ctxCancel(ErrCircuit)
		}
	}()

	log := logger(ctx)
	log.Info().Msg("creating circuit")

	create2 := cells.Create2Cell{
		CircuitID:     circuit.ID,
		HandshakeType: htype,
		Handshake:     hs,
	}
	if err := circuit.SendCell(&create2); err != nil {
		return nil, fail(ctx, ErrCircuit, "send CREATE2 failed", err)
	}

	var rawCell []byte
	select {
	case rawCell = <-circuit.Inbound:
	case <-circuit.Ctx.Done():
		return nil, fail(ctx, ErrCircuit, "circuit closed while waiting CREATED2", context.Cause(circuit.Ctx))
	}

	cell, err := circuit.Coder.ReadCell(bytes.NewReader(rawCell))
	if err != nil {
		return nil, fail(ctx, ErrCircuit, "decode CREATED2 failed", err)
	}
	if cell.ID() != cells.COMMAND_CREATED2 {
		log.Error().Uint8("cmd", cell.ID()).Type("cell_type", cell.ID()).Msg("expected CREATED2")
		return nil, Publicf(ErrProtocolViolation, "expected CREATED2, got command %d", cell.ID())
	}

	created2 := cell.(*cells.Created2Cell)
	if err := created2.DecodeHandshake(htype); err != nil {
		return nil, fail(ctx, ErrHandshake, "decode CREATED2 handshake failed", err)
	}

	keys := &crypto.CircuitKeys{}
	switch htype {
	case handshakes.HTYPE_NTOR:
		nths := hs.(*handshakes.Client_NTorHandshake)
		keys, err = nths.Derive(created2.Handshake.(*handshakes.Server_NTorHandshake), nths.KeyID)
		if err != nil {
			return nil, fail(ctx, ErrHandshake, "ntor derive failed", err)
		}
	default:
		return nil, Publicf(ErrHandshake, "unsupported handshake type %d", htype)
	}

	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)

	back, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return nil, fail(ctx, ErrCircuit, "init hop crypto failed", err)
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return nil, fail(ctx, ErrCircuit, "init hop crypto failed", err)
	}

	hop := hops.NewHop(circuit.Ctx, relay.NewDataCellCoder(back, forwards), rcvWindow, sndWindow)
	circuit.hops.Append(hop)
	go circuit.sendmeManage(0, hop)

	go circuit.writeLoop()
	go circuit.readloop()
	suc = true
	log.Info().Int("hops", circuit.hops.Len()).Msg("circuit created")
	return circuit, nil
}

func (c *Conn) NewFastCircuit(id uint32) (*Circuit, error) {
	var suc bool
	circID := shared.MSB(id)

	baseLog := logger(c.ctx).With().
		Str("component", "circuit").
		Uint32("circ_id", circID).
		Str("kind", "create_fast").
		Logger()
	ctx, cancel := context.WithCancelCause(withLogger(c.ctx, baseLog))

	circuit := &Circuit{
		conn:              c,
		ID:                circID,
		Inbound:           make(chan []byte, 512),
		WriteRelayCell:    make(chan RelayOut, 128),
		Ctx:               ctx,
		ctxCancel:         cancel,
		extended2Received: make(chan *relay.Extended2Cell, 1),
		streams: &streams{
			streams: make(map[uint16]*Stream),
		},
		SendMeVersion: 0,
		nextStreamID:  1,
		isUp:          true,
		Coder:         cells.NewCellCoder(cells.AllKnownCells),
	}

	xMaterial := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, xMaterial); err != nil {
		cancel(err)
		return nil, fail(ctx, ErrCircuit, "generate CREATE_FAST material failed", err)
	}

	createFast := cells.CreateFastCell{
		CircuitID: circID,
		X:         [20]byte(xMaterial),
	}

	c.circuits.Set(circID, circuit)
	defer func() {
		if !suc {
			c.circuits.Delete(circID)
			circuit.ctxCancel(ErrCircuit)
		}
	}()

	log := logger(ctx)
	log.Info().Msg("creating fast circuit")

	if err := circuit.SendCell(&createFast); err != nil {
		return nil, fail(ctx, ErrCircuit, "send CREATE_FAST failed", err)
	}

	var rawCell []byte
	select {
	case rawCell = <-circuit.Inbound:
	case <-circuit.Ctx.Done():
		return nil, fail(ctx, ErrCircuit, "circuit closed while waiting CREATED_FAST", context.Cause(circuit.Ctx))
	}
	cell, err := circuit.Coder.ReadCell(bytes.NewReader(rawCell))
	if err != nil {
		return nil, fail(ctx, ErrCircuit, "decode CREATED_FAST failed", err)
	}

	if cell.ID() != cells.COMMAND_CREATED_FAST {
		log.Error().Uint8("cmd", cell.ID()).Msg("expected CREATED_FAST")
		return nil, Publicf(ErrProtocolViolation, "expected CREATED_FAST, got command %d", cell.ID())
	}

	createdFast := cell.(*cells.CreatedFastCell)

	keys, err := crypto.DeriveKeysCreateFast([20]byte(xMaterial), createdFast.Y)
	if err != nil {
		return nil, fail(ctx, ErrHandshake, "CREATE_FAST key derive failed", err)
	}

	if !bytes.Equal(keys.KH, createdFast.KH[:]) {
		log.Error().Msg("CREATE_FAST KH mismatch")
		return nil, Public(ErrHandshake, "CREATE_FAST key confirmation failed")
	}

	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)

	back, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return nil, fail(ctx, ErrCircuit, "init hop crypto failed", err)
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return nil, fail(ctx, ErrCircuit, "init hop crypto failed", err)
	}

	hop := hops.NewHop(circuit.Ctx, relay.NewDataCellCoder(back, forwards), rcvWindow, sndWindow)
	circuit.hops.Append(hop)
	go circuit.sendmeManage(0, hop)

	suc = true
	go circuit.readloop()
	go circuit.writeLoop()
	log.Info().Int("hops", circuit.hops.Len()).Msg("fast circuit created")
	return circuit, nil
}

func (c *Circuit) Extend(lspecs []lspec.Lspec, htype uint16, handshake handshakes.Handshake) error {
	log := logger(c.Ctx)
	if c.hops.Len() == 0 {
		return fail(c.Ctx, ErrExtend, "cannot extend empty circuit", nil)
	}

	from := c.hops.Len()
	log.Info().Int("from_hops", from).Uint16("handshake", htype).Msg("extending circuit")

	extend2 := &relay.Extend2Cell{
		StreamID:  0,
		Lspecs:    lspecs,
		HType:     htype,
		Handshake: handshake,
	}

	dst := c.hops.Len() - 1
	body, err := c.hops.MarshalMessage(extend2, dst)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "encrypt EXTEND2 failed", err)
	}
	if err := c.SendCell(&cells.RelayEarlyCell{
		C: &cells.RelayCell{Body: body},
	}); err != nil {
		return fail(c.Ctx, ErrExtend, "send EXTEND2 failed", err)
	}

	var extended *relay.Extended2Cell
	select {
	case extended = <-c.extended2Received:
	case <-c.Ctx.Done():
		return fail(c.Ctx, ErrExtend, "circuit closed while waiting EXTENDED2", context.Cause(c.Ctx))
	}
	if err := extended.DecodeHandshake(htype); err != nil {
		return fail(c.Ctx, ErrHandshake, "decode EXTENDED2 handshake failed", err)
	}

	keys := &crypto.CircuitKeys{}
	switch htype {
	case handshakes.HTYPE_NTOR:
		nths := handshake.(*handshakes.Client_NTorHandshake)
		keys, err = nths.Derive(extended.Handshake.(*handshakes.Server_NTorHandshake), nths.KeyID)
		if err != nil {
			return fail(c.Ctx, ErrHandshake, "ntor derive on extend failed", err)
		}
	default:
		return Publicf(ErrHandshake, "unsupported handshake type %d", htype)
	}

	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)

	backwards, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "init hop crypto failed", err)
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "init hop crypto failed", err)
	}

	hop := hops.NewHop(c.Ctx, relay.NewDataCellCoder(backwards, forwards), rcvWindow, sndWindow)
	c.hops.Append(hop)
	go c.sendmeManage(c.hops.Len()-1, hop)
	log.Info().Int("hops", c.hops.Len()).Msg("circuit extended")
	return nil
}

func (c *Circuit) HopCount() int {
	return c.hops.Len()
}

// AppendE2EHop attaches an end-to-end (hidden-service) hop as the last hop of
// the circuit. Unlike Extend/ExtendTo it does NOT send an EXTEND2: the crypto
// keys are computed locally from the already-established rendezvous key seed
// (rend-spec-v3 §JOIN_REND). Kf/Kb are the forward/backward AES-128-CTR keys
// and Df/Db the SHA-1 digest seeds used to layer the e2e encryption on top of
// the existing circuit hops. The new hop inherits the same SENDME windows as
// the current exit hop.
func (c *Circuit) AppendE2EHop(Kf, Kb, Df, Db []byte) error {
	if c.hops.Len() == 0 {
		return fail(c.Ctx, ErrExtend, "cannot append e2e hop to empty circuit", nil)
	}
	last := c.hops.At(c.hops.Len() - 1)
	back, err := crypto.NewRunningValues(Kb, Db)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "init e2e hop crypto failed", err)
	}
	forwards, err := crypto.NewRunningValues(Kf, Df)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "init e2e hop crypto failed", err)
	}
	hop := hops.NewHop(c.Ctx, relay.NewDataCellCoder(back, forwards), last.Recv(), last.Send())
	c.hops.Append(hop)
	go c.sendmeManage(c.hops.Len()-1, hop)
	logger(c.Ctx).Info().Int("hops", c.hops.Len()).Msg("e2e hop appended")
	return nil
}

// SendHSControl relays a circuit-level hidden-service control cell (StreamID==0)
// through the onion encryption layers to the final hop. The cell is marshalled
// exactly like any other relay cell; the e2e hop (if present) supplies the
// outermost encryption layer.
func (c *Circuit) SendHSControl(cell relay.Cell) error {
	return c.SendCell(&cells.RelayCell{Body: mustMarshalRelay(c, cell)})
}

// mustMarshalRelay encrypts a relay cell for the circuit's outermost hop.
func mustMarshalRelay(c *Circuit, cell relay.Cell) []byte {
	dst := c.hops.Len() - 1
	body, err := c.hops.MarshalMessage(cell, dst)
	if err != nil {
		return nil
	}
	return body
}

func (c *Circuit) Close() error {
	logger(c.Ctx).Info().Msg("closing circuit")
	c.ctxCancel(ErrClosed)
	return nil
}

func (c *Circuit) handleCell(cell cells.Cell) {
	log := logger(c.Ctx)
	switch cell.ID() {
	case cells.COMMAND_DESTROY:
		reason := cell.(*cells.DestroyCell).Reason
		reasonS := common.DestroyGetReasonS(reason)
		log.Warn().Uint8("reason", reason).Str("reason_s", reasonS).Msg("DESTROY received")
		c.ctxCancel(Publicf(ErrCircuit, "destroyed: %s", reasonS))
		return
	default:
		log.Debug().Uint8("cmd", cell.ID()).Msg("unhandled link cell on circuit")
	}
}

func (c *Circuit) SendCell(cell cells.Cell) error {
	cell.SetCircuitID(c.ID)

	b, err := c.Coder.MarshalCell(cell)
	if err != nil {
		pub := fail(c.Ctx, ErrIO, "marshal cell failed", err)
		c.ctxCancel(pub)
		return pub
	}

	select {
	case c.conn.writeCall <- b:
	case <-c.Ctx.Done():
		return fail(c.Ctx, ErrClosed, "circuit closed", context.Cause(c.Ctx))
	}

	return nil
}
