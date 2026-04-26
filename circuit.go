package gonion

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"

	"git.servidordomal.fun/robogg133/gonion/internal/common"
	cells "git.servidordomal.fun/robogg133/gonion/pkg/cells/base"
	"git.servidordomal.fun/robogg133/gonion/pkg/cells/relay"
	"git.servidordomal.fun/robogg133/gonion/pkg/crypto"
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

	// Channels
	WriteRelayCell chan relay.Cell
	Inbound        chan []byte
	CloseCh        chan struct{}
	closeOnce      sync.Once
	sendMeReceived chan struct{}
}

func (c *Conn) NewFastCircuit(id uint32) (*Circuit, error) {
	var suc bool
	circID := cells.MSB(id)

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
			v: 1000,
		},
		SendWindow: &window{
			v: 1000,
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

func (c *Circuit) Close() error {
	c.teardown()
	return nil
}

func (c *Circuit) loop() {
	for {
		// Check circuit receive window and send SENDME if needed
		c.ReceiveWindow.mu.Lock()
		if c.ReceiveWindow.v%100 == 0 && c.ReceiveWindow.v != 1000 {
			cell := &cells.RelayCell{
				RelayCoder: c.Coder.RelayCoder,
				Cell: &relay.SendMeCell{
					StreamID:        0,
					Version:         c.SendMeVersion,
					Sha1ForLastCell: c.Backwards.GetLastSumDataCell(),
				},
			}
			if err := c.SendCell(cell); err != nil {
				c.ReceiveWindow.mu.Unlock()
				c.Close()
				return
			}
			c.ReceiveWindow.v += 100
		}
		c.ReceiveWindow.mu.Unlock()

		select {
		case rawCell := <-c.Inbound:
			cell, err := c.Coder.ReadCell(bytes.NewReader(rawCell))
			if err != nil {
				c.Close()
				return
			}

			if cell.ID() == cells.COMMAND_RELAY {
				relaycell := cell.(*cells.RelayCell).Cell

				if relaycell.GetStreamID() == 0 && relaycell.ID() == relay.COMMAND_SENDME {
					c.SendWindow.Add(100)
					continue
				}

				stream := c.streams.Get(relaycell.GetStreamID())
				if stream == nil {
					continue
				}
				select {
				case stream.Inbound <- relaycell:
				case <-stream.CloseCh:
				}
				continue
			}

			// Non-relay cells (DESTROY, etc.)
			go c.handleCell(cell)

		case relayCell := <-c.WriteRelayCell:
			cell := &cells.RelayCell{
				RelayCoder: c.Coder.RelayCoder,
				Cell:       relayCell,
			}
			c.SendCell(cell)

		case <-c.CloseCh:
			c.Close()
			return
		}
	}
}

func (c *Circuit) handleCell(cell cells.Cell) {
	switch cell.ID() {
	case cells.COMMAND_RELAY:
		relayCell := cell.(*cells.RelayCell)

		if relayCell.Cell.ID() == relay.COMMAND_SENDME && relayCell.Cell.GetStreamID() == 0 {
			c.SendWindow.Add(100)
			return
		}

		stream := c.streams.Get(relayCell.Cell.GetStreamID())
		if stream == nil {
			return
		}

		select {
		case stream.Inbound <- relayCell.Cell:
		case <-c.CloseCh:
			return
		case <-stream.CloseCh:
			return
		}

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
	c.SendWindow.mu.Lock()
	defer c.SendWindow.mu.Unlock()

	cell.SetCircuitID(c.ID)

	if c.SendWindow.v%100 == 0 && c.SendWindow.v != 1000 {
		select {
		case <-c.sendMeReceived:
			c.SendWindow.v += 100
		case <-c.CloseCh:
			return errors.New("circuit closed")
		}
	}

	b, err := c.Coder.MarshalCell(cell)
	if err != nil {
		c.Close()
		return err
	}

	select {
	case c.conn.writeCall <- b:
	case <-c.CloseCh:
		c.Close()
		return errors.New("circuit close")
	}

	return nil
}
