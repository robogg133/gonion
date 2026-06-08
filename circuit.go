package gonion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/robogg133/gonion/internal/shared"
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
	ReceiveWindow *window
	SendWindow    *window

	streams      *streams
	nextStreamID uint16

	// Crypto
	Backwards *crypto.RunningValues
	Forwards  *crypto.RunningValues

	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	// Channels
	WriteRelayCell chan relay.Cell
	Inbound        chan []byte
	CloseCh        chan struct{}
	closeOnce      sync.Once

	extended2Received chan *relay.Extended2Cell
	sendMeReceived    chan struct{}
}

func (c *Conn) NewCircuit(id uint32, htype uint16, hs handshakes.Handshake) (*Circuit, error) {
	suc := false
	circuit := &Circuit{
		conn:           c,
		ID:             shared.MSB(id),
		CloseCh:        make(chan struct{}),
		Inbound:        make(chan []byte, 512),
		WriteRelayCell: make(chan relay.Cell, 512),

		extended2Received: make(chan *relay.Extended2Cell, 1),
		sendMeReceived:    make(chan struct{}, 1),

		streams: &streams{
			streams: make(map[uint16]*Stream),
		},

		ReceiveWindow: &window{
			v:          1000,
			startValue: 1000,
			addValue:   100,
		},
		SendWindow: &window{
			v:          1000,
			startValue: 1000,
			addValue:   100,
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
			close(circuit.CloseCh)
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
	case <-c.closeCh:
		return nil, errors.New("connection closed")
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

	circuit.Backwards, err = crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return circuit, err
	}
	circuit.Forwards, err = crypto.NewRunningValues(keys.Kf, keys.Db)
	if err != nil {
		return circuit, err
	}

	circuit.Coder.RelayCoder = relay.NewDataCellCoder(circuit.Backwards, circuit.Forwards)

	go circuit.writeLoop()
	go circuit.readloop()
	suc = true
	return circuit, nil
}

func (c *Conn) NewFastCircuit(id uint32) (*Circuit, error) {
	var suc bool
	circID := shared.MSB(id)

	circuit := &Circuit{
		conn:           c,
		ID:             circID,
		CloseCh:        make(chan struct{}),
		Inbound:        make(chan []byte, 512),
		WriteRelayCell: make(chan relay.Cell, 128),
		sendMeReceived: make(chan struct{}, 1),

		streams: &streams{
			streams: make(map[uint16]*Stream),
		},

		ReceiveWindow: &window{
			v:          1000,
			startValue: 1000,
			addValue:   100,
		},
		SendWindow: &window{
			v:          1000,
			startValue: 1000,
			addValue:   100,
		},
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
			close(circuit.CloseCh)
		}
	}()

	circuit.Coder = cells.NewCellCoder(cells.AllKnownCells, &relay.RelayCellCoder{})

	if err := circuit.SendCell(&createFast); err != nil {
		return nil, err
	}

	var rawCell []byte
	select {
	case rawCell = <-circuit.Inbound:
	case <-c.closeCh:
		return nil, errors.New("connection closed")
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

	circuit.Backwards, err = crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return nil, err
	}
	circuit.Forwards, err = crypto.NewRunningValues(keys.Kf, keys.Df)
	if err != nil {
		return nil, err
	}

	circuit.Coder = cells.NewCellCoder(cells.AllKnownCells,
		relay.NewDataCellCoder(circuit.Backwards, circuit.Forwards),
	)

	suc = true
	go circuit.readloop()
	go circuit.writeLoop()
	return circuit, nil
}

func (c *Circuit) Extend(lspec []lspec.Lspec, htype uint16, handshake handshakes.Handshake) (*relay.RelayCellCoder, error) {

	extend2 := &relay.Extend2Cell{
		StreamID: 0,

		Lspecs:    lspec,
		HType:     htype,
		Handshake: handshake,
	}

	if err := c.SendCell(&cells.RelayEarlyCell{
		C: &cells.RelayCell{
			CircuitID:  c.ID,
			RelayCoder: c.Coder.RelayCoder,
			Cell:       extend2,
		},
	}); err != nil {
		return nil, err
	}

	extended := <-c.extended2Received
	if err := extended.DecodeHandshake(htype); err != nil {
		return nil, err
	}

	keys := &crypto.CircuitKeys{}
	var err error
	switch htype {
	case handshakes.HTYPE_NTOR:
		nths := handshake.(*handshakes.Client_NTorHandshake)
		keys, err = nths.Derive(extended.Handshake.(*handshakes.Server_NTorHandshake), nths.KeyID)
	}
	if err != nil {
		return nil, err
	}

	backwards, err := crypto.NewRunningValues(keys.Kb, keys.Db)
	if err != nil {
		return nil, err
	}
	forwards, err := crypto.NewRunningValues(keys.Kf, keys.Db)
	if err != nil {
		return nil, err
	}

	coder := relay.NewDataCellCoder(backwards, forwards)

	return coder, nil
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
		// #debug
		c.Close()
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

	if cell.ID() == cells.COMMAND_RELAY_EARLY {
		fmt.Println("RELAY_EARLY Len:", len(b))
		fmt.Println(hex.Dump(b))
		fmt.Println("//")
		fmt.Println(b)
	}

	select {
	case c.conn.writeCall <- b:
	case <-c.CloseCh:
		c.Close()
		return errors.New("circuit close")
	}

	return nil
}

func canContinue(r *common.RouterStatus) bool {
	if r.NTorOnionKey == nil {
		return false
	}
	if r.NodeID == [20]byte{} {
		return false
	}
	if r.IdEd25519 == nil {
		return false
	}

	return true
}
