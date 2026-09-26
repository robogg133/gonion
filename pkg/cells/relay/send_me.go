package relay

import (
	"encoding/binary"
	"fmt"
	"io"
)

const COMMAND_SENDME uint8 = 5

type SendMeCell struct {
	StreamID        uint16
	Version         uint8
	Sha1ForLastCell [20]byte
}

func (*SendMeCell) ID() uint8              { return COMMAND_SENDME }
func (c *SendMeCell) GetStreamID() uint16  { return c.StreamID }
func (c *SendMeCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *SendMeCell) Encode(w io.Writer) error {
	// Stream SENDMEs and version 0 circuit SENDMEs have empty bodies.
	if c.StreamID != 0 || c.Version == 0 {
		return nil
	}
	if c.Version != 1 {
		return fmt.Errorf("relay: unsupported SENDME version %d", c.Version)
	}
	if _, err := w.Write([]byte{1, 0, 20}); err != nil {
		return err
	}
	_, err := w.Write(c.Sha1ForLastCell[:])
	return err
}

func (c *SendMeCell) Decode(r io.Reader) error {
	c.Version, c.Sha1ForLastCell = 0, [20]byte{}
	if c.StreamID != 0 {
		return nil
	} // tor-spec 7.4: ignore stream body
	var version [1]byte
	n, err := io.ReadFull(r, version[:])
	if err == io.EOF && n == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	c.Version = version[0]
	if c.Version == 0 {
		return nil
	}
	if c.Version != 1 {
		return fmt.Errorf("relay: unsupported SENDME version %d", c.Version)
	}
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size < 20 || size > RELAY_BODY_LEN-3 {
		return fmt.Errorf("relay: invalid SENDME digest length %d", size)
	}
	if _, err := io.ReadFull(r, c.Sha1ForLastCell[:]); err != nil {
		return err
	}
	_, err = io.CopyN(io.Discard, r, int64(size-20))
	return err
}
