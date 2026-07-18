package relay

import (
	"bufio"
	"io"
)

const (
	COMMAND_BEGIN uint8 = 1
)

type BeginCell struct {
	StreamID uint16

	Addrport string
}

func (*BeginCell) ID() uint8              { return COMMAND_BEGIN }
func (c *BeginCell) GetStreamID() uint16  { return c.StreamID }
func (c *BeginCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *BeginCell) Encode(w io.Writer) error {
	addrB := []byte(c.Addrport)
	addrB = append(addrB, 0)

	if _, err := w.Write(addrB); err != nil {
		return err
	}
	return nil
}

func (c *BeginCell) Decode(r io.Reader) error {
	br := bufio.NewReader(r)
	s, err := br.ReadString(0)
	if err != nil {
		return err
	}
	c.Addrport = s

	return nil
}
