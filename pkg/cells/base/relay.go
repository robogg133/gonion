package cells

import (
	"fmt"
	"io"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

const COMMAND_RELAY uint8 = 3

type RelayCell struct {
	CircuitID uint32

	Hops []*relay.RelayCellCoder

	Cell relay.Cell
	hopN uint8
}

func (*RelayCell) ID() uint8               { return COMMAND_RELAY }
func (c *RelayCell) GetCircuitID() uint32  { return c.CircuitID }
func (c *RelayCell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *RelayCell) Encode(w io.Writer) error {
	payload, err := c.Hops[len(c.Hops)-1].Marshal(c.Cell)
	if err != nil {
		return err
	}
	for i := len(c.Hops) - 2; i >= 0; i-- {
		c.Hops[i].Forwards.XORKeyStream(payload[:], payload)
	}
	_, err = w.Write(payload)
	return err

}
func (c *RelayCell) Decode(r io.Reader) error {

	body := make([]byte, CELL_BODY_LEN)
	_, err := io.ReadFull(r, body)
	if err != nil {
		return err
	}
	for i, hop := range c.Hops {
		hop.Backwards.XORKeyStream(body[0:], body)
		if relay.IsDecrypted(body) {
			c.hopN = uint8(i)
			c.Cell, err = hop.UnmarshalPlain(body)
			return err
		}
	}

	return fmt.Errorf("Can't decrypt payload")
}

func (c *RelayCell) HopDestination() uint8 {
	return c.hopN
}
