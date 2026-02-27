package relay

import "io"

const (
	COMMAND_BEGIN uint8 = 1
)

type BeginCell struct {
	StreamID uint16

	Address string
}

func (*BeginCell) ID() uint8              { return COMMAND_BEGIN }
func (c *BeginCell) GetStreamID() uint16  { return c.StreamID }
func (c *BeginCell) SetStreamID(n uint16) { c.StreamID = n }

func (*BeginCell) Encode(io.Writer) error { return nil }
func (*BeginCell) Decode(io.Reader) error { return nil }
