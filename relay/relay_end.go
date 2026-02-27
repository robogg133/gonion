package relay

import "io"

const COMMAND_RELAY_END uint8 = 3

type RelayEndCell struct {
	StreamID uint16
}

func (*RelayEndCell) ID() uint8              { return COMMAND_RELAY_END }
func (c *RelayEndCell) GetStreamID() uint16  { return c.StreamID }
func (c *RelayEndCell) SetStreamID(n uint16) { c.StreamID = n }

func (*RelayEndCell) Encode(io.Writer) error { return nil }
func (*RelayEndCell) Decode(io.Reader) error { return nil }
