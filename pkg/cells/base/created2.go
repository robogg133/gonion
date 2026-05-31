package cells

import (
	"fmt"
	"io"

	"github.com/robogg133/gonion/pkg/handshakes"
)

const COMMAND_CREATED2 uint8 = 11

type Created2Cell struct {
	CircuitID uint32
	HType     uint8 // Needs to be specified

	Handshake handshakes.Handshake
}

func (*Created2Cell) ID() uint8               { return COMMAND_CREATED2 }
func (c *Created2Cell) GetCircuitID() uint32  { return c.CircuitID }
func (c *Created2Cell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *Created2Cell) Encode(w io.Writer) error { return nil }

func (c *Created2Cell) Decode(r io.Reader) error {
	c.Handshake = handshakes.Server_HandshakeType(c.HType)
	if c.Handshake == nil {
		return fmt.Errorf("cells/base/created2: invalid HTYPE: %d", c.HType)
	}

	return c.Handshake.Decode(r)
}
