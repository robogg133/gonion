package cells

import (
	"io"
)

const COMMAND_RELAY uint8 = 3

// RelayCell carries an opaque 509-byte relay body.
// Onion encrypt/decrypt is owned by internal/hops.Chain, not this type.
type RelayCell struct {
	CircuitID uint32
	Body      []byte
}

func (*RelayCell) ID() uint8               { return COMMAND_RELAY }
func (c *RelayCell) GetCircuitID() uint32  { return c.CircuitID }
func (c *RelayCell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *RelayCell) Encode(w io.Writer) error {
	if len(c.Body) == 0 {
		c.Body = make([]byte, CELL_BODY_LEN)
	}
	if len(c.Body) < CELL_BODY_LEN {
		padded := make([]byte, CELL_BODY_LEN)
		copy(padded, c.Body)
		c.Body = padded
	}
	_, err := w.Write(c.Body[:CELL_BODY_LEN])
	return err
}

func (c *RelayCell) Decode(r io.Reader) error {
	c.Body = make([]byte, CELL_BODY_LEN)
	_, err := io.ReadFull(r, c.Body)
	return err
}
