package cells

import "io"

const COMMAND_RELAY_EARLY uint8 = 9

type RelayEarlyCell struct {
	C *RelayCell
}

func (*RelayEarlyCell) ID() uint8 { return COMMAND_RELAY_EARLY }

func (c *RelayEarlyCell) GetCircuitID() uint32 {
	if c.C == nil {
		return 0
	}
	return c.C.CircuitID
}

func (c *RelayEarlyCell) SetCircuitID(n uint32) {
	if c.C == nil {
		c.C = &RelayCell{}
	}
	c.C.CircuitID = n
}

func (c *RelayEarlyCell) Encode(w io.Writer) error {
	if c.C == nil {
		c.C = &RelayCell{}
	}
	return c.C.Encode(w)
}

func (c *RelayEarlyCell) Decode(r io.Reader) error {
	if c.C == nil {
		c.C = &RelayCell{}
	}
	return c.C.Decode(r)
}
