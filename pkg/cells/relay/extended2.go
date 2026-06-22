package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/robogg133/gonion/pkg/handshakes"
)

const COMMAND_EXTENDED2 uint8 = 15

type Extended2Cell struct {
	StreamID uint16

	hs        []byte
	Handshake handshakes.Handshake
}

func (*Extended2Cell) ID() uint8              { return COMMAND_EXTENDED2 }
func (c *Extended2Cell) GetStreamID() uint16  { return c.StreamID }
func (c *Extended2Cell) SetStreamID(n uint16) { c.StreamID = n }

func (c *Extended2Cell) Encode(w io.Writer) error { return nil }

func (c *Extended2Cell) Decode(r io.Reader) error {

	length := uint16(0)
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}

	c.hs = make([]byte, length)
	_, err := io.ReadFull(r, c.hs)
	return err
}

func (c *Extended2Cell) DecodeHandshake(htype uint16) error {
	c.Handshake = handshakes.Server_HandshakeType(htype)
	if c.Handshake == nil {
		return fmt.Errorf("unknown handshake type: %d", htype)
	}
	return c.Handshake.Decode(bytes.NewReader(c.hs))
}
