package relay

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/robogg133/gonion/pkg/handshakes"
	"github.com/robogg133/gonion/pkg/lspec"
)

const COMMAND_EXTEND2 uint8 = 14

type Extend2Cell struct {
	StreamID uint16

	CircuitID uint32
	Lspecs    []lspec.Lspec

	HType     uint16
	Handshake handshakes.Handshake
}

func (*Extend2Cell) ID() uint8              { return COMMAND_EXTEND2 }
func (c *Extend2Cell) GetStreamID() uint16  { return c.StreamID }
func (c *Extend2Cell) SetStreamID(n uint16) { c.StreamID = n }

func (c *Extend2Cell) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, c.CircuitID); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint8(len(c.Lspecs))); err != nil {
		return err
	}

	for _, v := range c.Lspecs {
		if err := v.Write(w); err != nil {
			return err
		}
	}

	var buffer bytes.Buffer
	c.Handshake.Encode(&buffer)

	binary.Write(w, binary.BigEndian, c.HType)
	binary.Write(w, binary.BigEndian, uint16(buffer.Len()))

	_, err := w.Write(buffer.Bytes())
	return err
}

func (*Extend2Cell) Decode(r io.Reader) error {
	// TODO
	return nil
}
