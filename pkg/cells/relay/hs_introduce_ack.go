package relay

import (
	"encoding/binary"
	"fmt"
	"io"
)

// INTRO_ACK statuses (FMT_INTRO_ACK), wire values are uint16 in range 0x00..0x03.
const (
	INTRO_ACK_SUCCESS        uint16 = 0x00
	INTRO_ACK_NOT_RECOGNIZED uint16 = 0x01
	INTRO_ACK_BAD_FORMAT     uint16 = 0x02
	INTRO_ACK_CANT_RELAY     uint16 = 0x03
)

// IntroduceAckCell acknowledges an INTRODUCE1 at the intro point.
//
//	STATUS(2) N_EXTENSIONS(1) exts
type IntroduceAckCell struct {
	StreamID uint16
	Status   uint16
	Exts     []Ext
}

func (*IntroduceAckCell) ID() uint8              { return COMMAND_INTRODUCE_ACK }
func (c *IntroduceAckCell) GetStreamID() uint16  { return c.StreamID }
func (c *IntroduceAckCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *IntroduceAckCell) Encode(w io.Writer) error {
	if c.Status > 0x03 {
		return fmt.Errorf("relay: INTRO_ACK status out of range: %d", c.Status)
	}
	if err := binary.Write(w, binary.BigEndian, c.Status); err != nil {
		return err
	}
	return encodeExts(w, c.Exts)
}
func (c *IntroduceAckCell) Decode(r io.Reader) error {
	var status [2]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return err
	}
	c.Status = binary.BigEndian.Uint16(status[:])
	var err error
	c.Exts, err = decodeExts(r)
	return err
}