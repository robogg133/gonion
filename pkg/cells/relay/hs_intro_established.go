package relay

import "io"

// IntroEstablishedCell acknowledges an ESTABLISH_INTRO at the intro point
// (tor RELAY_COMMAND_INTRO_ESTABLISHED = 38). The body is a trn_extension; a
// legacy node accepts an empty body.
type IntroEstablishedCell struct {
	StreamID uint16
	Exts     []Ext
}

func (*IntroEstablishedCell) ID() uint8              { return COMMAND_INTRO_ESTABLISHED }
func (c *IntroEstablishedCell) GetStreamID() uint16  { return c.StreamID }
func (c *IntroEstablishedCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *IntroEstablishedCell) Encode(w io.Writer) error {
	return encodeExts(w, c.Exts)
}
func (c *IntroEstablishedCell) Decode(r io.Reader) error {
	exts, err := decodeExts(r)
	c.Exts = exts
	if err == io.EOF {
		// Legacy empty body.
		return nil
	}
	return err
}