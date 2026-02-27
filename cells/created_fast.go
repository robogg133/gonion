package cells

import (
	"io"
)

type CreatedFastCell struct {
	CircuitID uint32

	Y  [20]byte
	KH [20]byte
}

func (*CreatedFastCell) ID() uint8               { return COMMAND_CREATED_FAST }
func (c *CreatedFastCell) GetCircuitID() uint32  { return c.CircuitID }
func (c *CreatedFastCell) SetCircuitID(n uint32) { c.CircuitID = n }

func (*CreatedFastCell) Encode(io.Writer) error { return nil }

func (c *CreatedFastCell) Decode(r io.Reader) error {

	buff := make([]byte, 20)

	// Reading Y
	if _, err := io.ReadFull(r, buff); err != nil {
		return err
	}
	c.Y = [20]byte(buff)

	// Reading KH
	if _, err := io.ReadFull(r, buff); err != nil {
		return err
	}

	c.KH = [20]byte(buff)

	// Discarting the rest of the cell
	_, err := io.CopyN(io.Discard, r, CELL_BODY_LEN-40)

	return err
}
