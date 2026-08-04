package relay

import "io"

// RendezvousEstablishedCell acknowledges an ESTABLISH_RENDEZVOUS. Body is
// typically empty; clients MUST ignore any extra bytes.
type RendezvousEstablishedCell struct {
	StreamID uint16
	Exts     []Ext
}

func (*RendezvousEstablishedCell) ID() uint8 { return COMMAND_RENDEZVOUS_ESTABLISHED }
func (c *RendezvousEstablishedCell) GetStreamID() uint16 { return c.StreamID }
func (c *RendezvousEstablishedCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *RendezvousEstablishedCell) Encode(w io.Writer) error {
	return encodeExts(w, c.Exts)
}
func (c *RendezvousEstablishedCell) Decode(r io.Reader) error {
	exts, err := decodeExts(r)
	c.Exts = exts
	return err
}