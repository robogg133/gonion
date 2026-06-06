package cells

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/robogg133/gonion/pkg/handshakes"
)

const COMMAND_CREATE2 uint8 = 10

type Create2Cell struct {
	CircuitID uint32

	HandshakeType uint16
	Handshake     handshakes.Handshake
}

func (*Create2Cell) ID() uint8               { return COMMAND_CREATE2 }
func (c *Create2Cell) GetCircuitID() uint32  { return c.CircuitID }
func (c *Create2Cell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *Create2Cell) Encode(w io.Writer) error {
	var buffer bytes.Buffer
	if err := c.Handshake.Encode(&buffer); err != nil {
		return err
	}
	hs := buffer.Bytes()

	binary.Write(w, binary.BigEndian, c.HandshakeType)
	binary.Write(w, binary.BigEndian, uint16(len(hs)))
	_, err := w.Write(hs)
	return err
}

func (c *Create2Cell) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &c.HandshakeType); err != nil {
		return err
	}

	length := uint16(0)
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}

	c.Handshake = handshakes.Client_HandshakeType(c.HandshakeType)
	err := c.Handshake.Decode(io.LimitReader(r, int64(length)))
	return err
}
