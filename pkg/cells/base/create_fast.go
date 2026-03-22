package cells

import (
	"io"
)

const (
	COMMAND_CREATE_FAST  uint8 = 5
	COMMAND_CREATED_FAST uint8 = 6
)

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

func (*CreateFastCell) Decode(io.Reader) error { return nil }
