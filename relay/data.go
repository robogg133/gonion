package relay

import (
	"io"
)

const COMMAND_DATA uint8 = 2

type DataCell struct {
	StreamID uint16

	Payload []byte
}

func (*DataCell) ID() uint8              { return COMMAND_DATA }
func (c *DataCell) GetStreamID() uint16  { return c.StreamID }
func (c *DataCell) setStreamID(n uint16) { c.StreamID = n }

func (c *DataCell) Encode(w io.Writer) error {
	_, err := w.Write(c.Payload)
	return err
}

func (c *DataCell) Decode(r io.Reader) error {
	var err error
	c.Payload, err = io.ReadAll(r)
	if err != nil {
		switch err {
		case io.EOF:
			return nil
		case io.ErrUnexpectedEOF:
			return nil
		default:
			return err
		}
	}
	return nil
}
