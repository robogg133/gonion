package relay

import "io"

// Introduce1Cell asks an intro point to relay an introduction. Wire per
// FMT_INTRO1; Encrypted is the sealed intro payload (up to end of body).
type Introduce1Cell struct {
	StreamID  uint16
	introHead // LegacyKeyID, AuthKey, Exts
	Encrypted []byte
}

func (*Introduce1Cell) ID() uint8              { return COMMAND_INTRODUCE1 }
func (c *Introduce1Cell) GetStreamID() uint16  { return c.StreamID }
func (c *Introduce1Cell) SetStreamID(n uint16) { c.StreamID = n }

func (c *Introduce1Cell) Encode(w io.Writer) error {
	if err := c.introHead.encodeIntroHead(w); err != nil {
		return err
	}
	_, err := w.Write(c.Encrypted)
	return err
}
func (c *Introduce1Cell) Decode(r io.Reader) error {
	if err := c.introHead.decodeIntroHead(r); err != nil {
		return err
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	c.Encrypted = rest
	return nil
}
