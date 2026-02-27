package relay

import (
	"encoding/binary"
	"io"
)

const COMMAND_SENDME uint8 = 5

type SendMeCell struct {
	StreamID uint16

	Version uint8

	Sha1ForLastCell [20]byte
}

func (*SendMeCell) ID() uint8              { return COMMAND_SENDME }
func (c *SendMeCell) GetStreamID() uint16  { return c.StreamID }
func (c *SendMeCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *SendMeCell) Encode(w io.Writer) error {

	if _, err := w.Write([]byte{c.Version}); err != nil {
		return err
	}

	// Length
	twenty := make([]byte, 2)
	binary.BigEndian.PutUint16(twenty, 20)
	if _, err := w.Write(twenty); err != nil {
		return err
	}

	// SHA1
	_, err := w.Write(c.Sha1ForLastCell[:])
	return err
}
func (c *SendMeCell) Decode(r io.Reader) error {

	ver := make([]byte, 1)

	if _, err := io.ReadFull(r, ver); err != nil {
		return err
	}
	c.Version = ver[0]

	lengthB := make([]byte, 2)
	if _, err := io.ReadFull(r, lengthB); err != nil {
		return err
	}

	lenght := binary.BigEndian.Uint16(lengthB)
	lengthB = nil

	sum := make([]byte, lenght)
	if _, err := io.ReadFull(r, sum); err != nil {
		return err
	}

	c.Sha1ForLastCell = [20]byte(sum)

	return nil
}
