package gonion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"

	"github.com/robogg133/gonion/connection/cells"
	"github.com/robogg133/gonion/relay"
	"github.com/robogg133/gonion/tor_crypto"
)

type Circuit struct {
	// Info
	conn *Conn

	ID uint32
	mu sync.RWMutex

	Translator cells.CellTranslator

	ReceiveWindow uint16
	SendWindow    uint16

	streams      map[uint16]*Stream
	nextStreamID uint16

	// Crypto
	DigestFoward    []byte
	DigestBackwards []byte

	ForwardDigest         hash.Hash
	BackWardsDigest       hash.Hash
	KeyForwardAES128CTR   cipher.Stream
	KeyBackwardsAES128CTR cipher.Stream

	// Channels
	WriteRelayCell chan relay.Cell
	Inbound        chan []byte
	CloseCh        chan struct{}
	closeOnce      sync.Once
}

// NewFastCircuit creates an one hop circuit with CREATE_FAST
func (c *Conn) NewFastCircuit(id uint32) (*Circuit, error) {
	var suc bool
	circID := cells.MSB(id)

	circuit := &Circuit{
		conn:           c,
		ID:             circID,
		CloseCh:        make(chan struct{}),
		Inbound:        make(chan []byte, 128),
		WriteRelayCell: make(chan relay.Cell, 128),
		streams:        make(map[uint16]*Stream),
		ReceiveWindow:  1000,
		SendWindow:     1000,
		nextStreamID:   1,
	}

	xMaterial := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, xMaterial); err != nil {
		return nil, err
	}

	createFast := cells.CreateFastCell{
		CircuitID: circID,
		X:         [20]byte(xMaterial),
	}

	c.mu.Lock()
	c.circuits[circID] = circuit
	c.mu.Unlock()

	defer func() {
		if !suc {
			c.mu.Lock()
			delete(c.circuits, circID)
			c.mu.Unlock()
			close(circuit.CloseCh)
		}
	}()

	circuit.Translator = cells.NewCellTranslator(cells.AllKnownCells, relay.RelayCellConstructor{})
	if err := circuit.SendCell(&createFast); err != nil {
		return nil, err
	}

	var rawCell []byte
	select {
	case rawCell = <-circuit.Inbound:
	case <-c.closeCh:
		return nil, errors.New("connection closed")
	}
	cell, err := circuit.Translator.ReadCell(bytes.NewReader(rawCell))
	if err != nil {
		return nil, err
	}

	if cell.ID() != cells.COMMAND_CREATED_FAST {
		return nil, fmt.Errorf("protocol violation creating circuit")
	}

	createdFast := cell.(*cells.CreatedFastCell)

	keys, err := tor_crypto.DeriveKeysCreateFast([20]byte(xMaterial), createdFast.Y)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(keys.KH, createdFast.KH[:]) {
		return nil, fmt.Errorf("KH key don't match")
	}

	circuit.BackWardsDigest = sha1.New()
	circuit.BackWardsDigest.Write(keys.Db)

	circuit.ForwardDigest = sha1.New()
	circuit.ForwardDigest.Write(keys.Df)

	block, err := aes.NewCipher(keys.Kf)
	if err != nil {
		return nil, err
	}
	tmp := make([]byte, 16)
	circuit.KeyForwardAES128CTR = cipher.NewCTR(block, tmp)

	block2, err := aes.NewCipher(keys.Kb)
	if err != nil {
		return nil, err
	}
	tmp = make([]byte, 16)
	circuit.KeyBackwardsAES128CTR = cipher.NewCTR(block2, tmp)

	circuit.Translator = cells.NewCellTranslator(cells.AllKnownCells,
		relay.NewDataCellConstructor(
			circuit.BackWardsDigest,
			circuit.ForwardDigest,
			circuit.KeyBackwardsAES128CTR,
			circuit.KeyForwardAES128CTR,
			&circuit.DigestBackwards,
			&circuit.DigestFoward,
			&circuit.mu,
		))

	suc = true
	go circuit.loop()
	return circuit, nil
}

func (c *Circuit) SendCell(cell cells.Cell) error {
	cell.SetCircuitID(c.ID)

	b, err := c.Translator.WriteCellBytes(cell)
	if err != nil {
		return err
	}

	select {
	case c.conn.writeCall <- b:
	case <-c.CloseCh:
		return errors.New("circuit closed")
	case <-c.conn.closeCh:
		return errors.New("connection closed")
	}
	return nil
}

func (c *Circuit) loop() {
	for {
		select {
		case <-c.CloseCh:
			c.teardown()
			return
		default:
		}

		func() {
			c.mu.RLock()
			rcvWindow := c.ReceiveWindow
			sum := c.DigestBackwards
			c.mu.RUnlock()
			if rcvWindow%100 == 0 && rcvWindow != 1000 {
				sendme := cells.RelayCell{
					CircuitID:   c.ID,
					Constructor: &c.Translator.Constructor,
					Cell: &relay.SendMeCell{
						StreamID:        0,
						Version:         1,
						Sha1ForLastCell: [20]byte(sum),
					},
				}
				select {
				case c.WriteRelayCell <- sendme.Cell:
					c.mu.Lock()
					c.ReceiveWindow += 100
					c.mu.Unlock()
				case <-c.CloseCh:
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
		}()

		select {
		case rawCell := <-c.Inbound:
			cell, err := c.Translator.ReadCell(bytes.NewReader(rawCell))
			if err != nil {
				c.Close()
				return
			}
			c.handleCell(cell)
		case relaycell := <-c.WriteRelayCell:
			relayCell := &cells.RelayCell{
				CircuitID:   c.ID,
				Constructor: &c.Translator.Constructor,
				Cell:        relaycell,
			}
			if err := c.SendCell(relayCell); err != nil {
				c.Close()
				return
			}
		case <-c.CloseCh:
			c.teardown()
			return
		}
	}
}

func (c *Circuit) handleCell(cell cells.Cell) {
	switch cell.ID() {
	case cells.COMMAND_RELAY:
		relayCell := cell.(*cells.RelayCell)

		if relayCell.Cell.ID() == relay.COMMAND_SENDME && relayCell.Cell.GetStreamID() == 0 {
			c.mu.Lock()
			c.SendWindow += 100
			c.mu.Unlock()
			return
		}

		c.mu.RLock()
		stream := c.streams[relayCell.Cell.GetStreamID()]
		c.mu.RUnlock()
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
		fmt.Println("RECEIVED DESTROY")
		fmt.Printf("REASON %d\n", cell.(*cells.DestroyCell).Reason)
		c.Close()
		return
	}
}

func (c *Circuit) Close() {
	c.closeOnce.Do(func() {
		close(c.CloseCh)
	})
}

func (c *Circuit) teardown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.streams {
		s.Close()
	}
	c.streams = make(map[uint16]*Stream)
}
