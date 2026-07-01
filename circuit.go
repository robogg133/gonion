package gonion

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

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
	// Info
	conn *Conn

	ID uint32

	isUp bool

	Coder *cells.CellCoder

	SendMeVersion uint8

	streams      *streams
	nextStreamID uint16

	// Crypto
	hops        []*relay.RelayCellCoder
	hopsWindows []struct {
		receive *window.Window
		send    *window.Window
	}

	// Channels
	WriteRelayCell chan struct {
		relay.Cell
		uint8
	}
	Inbound   chan []byte
	Ctx       context.Context
	ctxCancel context.CancelCauseFunc
	closeOnce sync.Once

	extended2Received chan *relay.Extended2Cell
	sendMeReceived    chan struct{}
}

func (c *Conn) NewCircuit(id uint32, htype uint16, hs handshakes.Handshake) (*Circuit, error) {
	suc := false
	ctx, cancel := context.WithCancelCause(c.ctx)
	circuit := &Circuit{
		conn:    c,
		ID:      shared.MSB(id),
		Inbound: make(chan []byte, 2048),
		WriteRelayCell: make(chan struct {
			relay.Cell
			uint8
		}, 512),

		Ctx:               ctx,
		ctxCancel:         cancel,
		extended2Received: make(chan *relay.Extended2Cell, 1),
		sendMeReceived:    make(chan struct{}, 1),

		streams: &streams{
			streams: make(map[uint16]*Stream),
		},

		SendMeVersion: 1,
		nextStreamID:  1,
		isUp:          true,

		Coder: cells.NewCellCoder(cells.AllKnownCells, &relay.RelayCellCoder{}), // Starting empty relay cell coder
	}
	c.circuits.Set(circuit.ID, circuit)
	defer func() {
		if !suc {
			c.circuits.Delete(circuit.ID)
			circuit.ctxCancel(fmt.Errorf("error starting circuit"))
		}
	}()

	create2 := cells.Create2Cell{
		CircuitID: circuit.ID,

		HandshakeType: htype,
		Handshake:     hs,
	}
	if err := circuit.SendCell(&create2); err != nil {
		return circuit, err
	}

	var rawCell []byte
	select {
	case rawCell = <-circuit.Inbound:
	case <-circuit.Ctx.Done():
		return nil, circuit.Ctx.Err()
	}

	cell, err := circuit.Coder.ReadCell(bytes.NewReader(rawCell))
	if err != nil {
		return circuit, err
	}
	if cell.ID() != cells.COMMAND_CREATED2 {
		return circuit, fmt.Errorf("NewCircuit: Protocol violation expecting CREATED2(%d) got %d ", cells.COMMAND_CREATE2, cell.ID())
	}

	created2 := cell.(*cells.Created2Cell)
	if err := created2.DecodeHandshake(htype); err != nil {
		return circuit, err
	}

	keys := &crypto.CircuitKeys{}
	switch htype {
	case handshakes.HTYPE_NTOR:
		nths := hs.(*handshakes.Client_NTorHandshake)
		keys, err = nths.Derive(created2.Handshake.(*handshakes.Server_NTorHandshake), nths.KeyID)
	}
	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)

	back, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return circuit, err
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return circuit, err
	}

	circuit.hops = []*relay.RelayCellCoder{relay.NewDataCellCoder(back, forwards)}
	circuit.hopsWindows = []struct {
		receive *window.Window
		send    *window.Window
	}{
		{
			receive: rcvWindow,
			send:    sndWindow,
		},
	}
	circuit.Coder.Hops = circuit.hops

	go circuit.writeLoop()
	go circuit.readloop()
	suc = true
	return circuit, nil
}

func (c *Conn) NewFastCircuit(id uint32) (*Circuit, error) {
	var suc bool
	circID := shared.MSB(id)
	ctx, cancel := context.WithCancelCause(c.ctx)

	circuit := &Circuit{
		conn:    c,
		ID:      circID,
		Inbound: make(chan []byte, 512),
		WriteRelayCell: make(chan struct {
			relay.Cell
			uint8
		}, 128),
		sendMeReceived: make(chan struct{}, 1),
		Ctx:            ctx,
		ctxCancel:      cancel,

		streams: &streams{
			streams: make(map[uint16]*Stream),
		},
		hops: make([]*relay.RelayCellCoder, 0),
		hopsWindows: make([]struct {
			receive *window.Window
			send    *window.Window
		}, 0),

		SendMeVersion: 0,

		nextStreamID: 1,
		isUp:         true,
	}

	xMaterial := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, xMaterial); err != nil {
		return nil, err
	}

	createFast := cells.CreateFastCell{
		CircuitID: circID,
		X:         [20]byte(xMaterial),
	}

	c.circuits.Set(circID, circuit)

	defer func() {
		if !suc {
			c.circuits.Delete(circID)
			circuit.ctxCancel(fmt.Errorf("error starting circuit"))
		}
	}()

	circuit.Coder = cells.NewCellCoder(cells.AllKnownCells, &relay.RelayCellCoder{})

	if err := circuit.SendCell(&createFast); err != nil {
		return nil, err
	}

	var rawCell []byte
	select {
	case rawCell = <-circuit.Inbound:
	case <-circuit.Ctx.Done():
		return nil, circuit.Ctx.Err()
	}
	cell, err := circuit.Coder.ReadCell(bytes.NewReader(rawCell))
	if err != nil {
		return nil, err
	}

	if cell.ID() != cells.COMMAND_CREATED_FAST {
		return nil, fmt.Errorf("protocol violation creating circuit")
	}

	createdFast := cell.(*cells.CreatedFastCell)

	keys, err := crypto.DeriveKeysCreateFast([20]byte(xMaterial), createdFast.Y)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(keys.KH, createdFast.KH[:]) {
		return nil, fmt.Errorf("KH key don't match")
	}

	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)

	back, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return nil, err
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return nil, err
	}

	circuit.hops = []*relay.RelayCellCoder{relay.NewDataCellCoder(back, forwards)}
	circuit.hopsWindows = []struct {
		receive *window.Window
		send    *window.Window
	}{
		{
			receive: rcvWindow,
			send:    sndWindow,
		},
	}
	circuit.Coder.Hops = circuit.hops

	suc = true
	go circuit.readloop()
	go circuit.writeLoop()
	return circuit, nil
}

func (c *Circuit) Extend(lspec []lspec.Lspec, htype uint16, handshake handshakes.Handshake) error {

	extend2 := &relay.Extend2Cell{
		StreamID: 0,

		Lspecs:    lspec,
		HType:     htype,
		Handshake: handshake,
	}

	if err := c.SendCell(&cells.RelayEarlyCell{
		C: &cells.RelayCell{
			CircuitID: c.ID,
			Hops:      c.hops, Cell: extend2,
		},
	}); err != nil {
		return err
	}

	extended := <-c.extended2Received
	if err := extended.DecodeHandshake(htype); err != nil {
		return err
	}

	keys := &crypto.CircuitKeys{}
	var err error
	switch htype {
	case handshakes.HTYPE_NTOR:
		nths := handshake.(*handshakes.Client_NTorHandshake)
		keys, err = nths.Derive(extended.Handshake.(*handshakes.Server_NTorHandshake), nths.KeyID)
	}
	if err != nil {
		return err
	}

	rcvWindow := window.NewWindow(1000, 100)
	sndWindow := window.NewWindow(1000, 100)

	backwards, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return err
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return err
	}

	c.hops = append(c.hops, relay.NewDataCellCoder(backwards, forwards))
	c.hopsWindows = append(c.hopsWindows, struct {
		receive *window.Window
		send    *window.Window
	}{
		receive: rcvWindow,
		send:    sndWindow,
	})

	return nil
}

func (c *Circuit) Close() error {
	c.teardown()
	return nil
}

func (c *Circuit) handleCell(cell cells.Cell) {
	switch cell.ID() {
	case cells.COMMAND_DESTROY:
		// #debug
		fmt.Printf("RECEIVED DESTROY: (%d) %s\n", cell.(*cells.DestroyCell).Reason, common.DestroyGetReasonS(cell.(*cells.DestroyCell).Reason))
		c.ctxCancel(fmt.Errorf("destroyed: reason=%d (%s)", cell.(*cells.DestroyCell).Reason, common.DestroyGetReasonS(cell.(*cells.DestroyCell).Reason)))
		// #debug
		return
	}
}

func (c *Circuit) teardown() {
	c.streams.mu.Lock()
	defer c.streams.mu.Unlock()
	for _, s := range c.streams.streams {
		s.Close()
	}
}

func (c *Circuit) SendCell(cell cells.Cell) error {
	cell.SetCircuitID(c.ID)

	b, err := c.Coder.MarshalCell(cell)
	if err != nil {
		c.Close()
		return err
	}

	select {
	case c.conn.writeCall <- b:
	case <-c.Ctx.Done():
		c.Close()
		return c.Ctx.Err()
	}

	return nil
}
