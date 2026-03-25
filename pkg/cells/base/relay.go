package cells

import (
	"io"

	"git.servidordomal.fun/robogg133/gonion/pkg/cells/relay"
)

const COMMAND_RELAY uint8 = 3

type RelayCell struct {
	CircuitID uint32

	RelayCoder *relay.RelayCellCoder

	Cell relay.Cell
}

func (*RelayCell) ID() uint8               { return COMMAND_RELAY }
func (c *RelayCell) GetCircuitID() uint32  { return c.CircuitID }
func (c *RelayCell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *RelayCell) Encode(w io.Writer) error {

	b, err := c.RelayCoder.Marshal(c.Cell)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err

}
func (c *RelayCell) Decode(r io.Reader) error {

	body := make([]byte, CELL_BODY_LEN)
	_, err := io.ReadFull(r, body)
	if err != nil {
		return err
	}

	c.Cell, err = c.RelayCoder.Unmarshal(body)

	return err
}
