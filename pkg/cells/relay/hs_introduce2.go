package relay

import "io"

// Introduce2Cell, sent from the intro point to the hidden service with the
// client's introduction request. Wire per FMT_INTRO2; Payload is the sealed
// intro (the ENCRYPTED portion forwarded verbatim by the intro point).
type Introduce2Cell struct {
	StreamID  uint16
	introHead // LegacyKeyID, AuthKey, Exts
	Payload   []byte
}

func (*Introduce2Cell) ID() uint8              { return COMMAND_INTRODUCE2 }
func (c *Introduce2Cell) GetStreamID() uint16  { return c.StreamID }
func (c *Introduce2Cell) SetStreamID(n uint16) { c.StreamID = n }

func (c *Introduce2Cell) Encode(w io.Writer) error {
	if err := c.introHead.encodeIntroHead(w); err != nil {
		return err
	}
	_, err := w.Write(c.Payload)
	return err
}
func (c *Introduce2Cell) Decode(r io.Reader) error {
	if err := c.introHead.decodeIntroHead(r); err != nil {
		return err
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	c.Payload = rest
	return nil
}
