package cells

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/robogg133/gonion/pkg/handshakes"
)

const COMMAND_CREATED2 uint8 = 11

type Created2Cell struct {
	CircuitID uint32
	hs        []byte

	Handshake handshakes.Handshake // MAKE SURE YOU USED DecodeHandshake METHOD BEFORE TRYING TO USE THIS VAR
}

func (*Created2Cell) ID() uint8               { return COMMAND_CREATED2 }
func (c *Created2Cell) GetCircuitID() uint32  { return c.CircuitID }
func (c *Created2Cell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *Created2Cell) Encode(w io.Writer) error { return nil }

func (c *Created2Cell) Decode(r io.Reader) error {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return err
	}

	c.hs = make([]byte, n)

	_, err := io.ReadFull(r, c.hs)
	return err
}

func (c *Created2Cell) DecodeHandshake(htype uint16) error {
	c.Handshake = handshakes.Server_HandshakeType(htype)
	if c.Handshake == nil {
		return fmt.Errorf("unknown handshake type: %d", htype)
	}
	return c.Handshake.Decode(bytes.NewReader(c.hs))
}
