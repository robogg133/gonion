package cells

import "io"

const COMMAND_RELAY_EARLY uint8 = 9

type RelayEarlyCell struct {
	c *RelayCell
}

func (*RelayEarlyCell) ID() uint8               { return COMMAND_RELAY_EARLY }
func (c *RelayEarlyCell) GetCircuitID() uint32  { return c.c.CircuitID }
func (c *RelayEarlyCell) SetCircuitID(n uint32) { c.c.CircuitID = n }

func (c *RelayEarlyCell) Encode(w io.Writer) error { return c.c.Encode(w) }
func (c *RelayEarlyCell) Decode(r io.Reader) error { return c.c.Decode(r) }
