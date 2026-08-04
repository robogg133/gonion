package relay

import "io"

// INTRO_ACK statuses (FMT_INTRO_ACK): 0x00 success ... 0x03 can't relay.
const (
	INTRO_ACK_SUCCESS        byte = 0x00
	INTRO_ACK_NOT_RECOGNIZED byte = 0x01
	INTRO_ACK_BAD_FORMAT     byte = 0x02
	INTRO_ACK_CANT_RELAY     byte = 0x03
)

// IntroduceAckCell acknowledges an INTRODUCE1 at the intro point.
//
//	STATUS(2) N_EXTENSIONS(1) exts
type IntroduceAckCell struct {
	StreamID uint16
	Status   byte
	Exts     []Ext
}

func (*IntroduceAckCell) ID() uint8              { return COMMAND_INTRODUCE_ACK }
func (c *IntroduceAckCell) GetStreamID() uint16  { return c.StreamID }
func (c *IntroduceAckCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *IntroduceAckCell) Encode(w io.Writer) error {
	if err := writeByte(w, c.Status); err != nil {
		return err
	}
	return encodeExts(w, c.Exts)
}
func (c *IntroduceAckCell) Decode(r io.Reader) error {
	st, err := readLenByte(r)
	if err != nil {
		return err
	}
	c.Status = st
	c.Exts, err = decodeExts(r)
	return err
}