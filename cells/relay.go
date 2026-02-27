package cells

import (
	"io"

	"github.com/robogg133/gonion/relay"
)

const COMMAND_RELAY uint8 = 3

type RelayCell struct {
	CircuitID uint32

	Constructor *relay.RelayCellConstructor

	Cell relay.Cell
}

func (*RelayCell) ID() uint8               { return COMMAND_RELAY }
func (c *RelayCell) GetCircuitID() uint32  { return c.CircuitID }
func (c *RelayCell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *RelayCell) Encode(w io.Writer) error {

	b, err := c.Constructor.Marshal(c.Cell)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err

}
func (c *RelayCell) Decode(r io.Reader) error {

	body := make([]byte, CELL_BODY_LEN)
	_, err := r.Read(body)
	if err != nil {
		return err
	}

	c.Cell, err = c.Constructor.Unmarshal(body)

	return err
}
