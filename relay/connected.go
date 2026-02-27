package relay

import "io"

const COMMAND_CONNECTED uint8 = 4

type ConnectedCell struct {
	StreamID uint16
}

func (*ConnectedCell) ID() uint8              { return COMMAND_CONNECTED }
func (c *ConnectedCell) GetStreamID() uint16  { return c.StreamID }
func (c *ConnectedCell) SetStreamID(n uint16) { c.StreamID = n }

func (*ConnectedCell) Encode(io.Writer) error { return nil }
func (*ConnectedCell) Decode(io.Reader) error { return nil }
