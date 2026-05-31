package cells

import (
	"io"
)

const COMMAND_CREATE_FAST uint8 = 5

type CreateFastCell struct {
	CircuitID uint32
	X         [20]byte // X is just 20 random bytes
}

func (*CreateFastCell) ID() uint8               { return COMMAND_CREATE_FAST }
func (c *CreateFastCell) GetCircuitID() uint32  { return c.CircuitID }
func (c *CreateFastCell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *CreateFastCell) Encode(w io.Writer) error {
	_, err := w.Write(c.X[:])
	return err
}

func (c *CreateFastCell) Decode(r io.Reader) error {
	x := make([]byte, 20)
	_, err := io.ReadFull(r, x)
	c.X = [20]byte(x)
	return err
}
