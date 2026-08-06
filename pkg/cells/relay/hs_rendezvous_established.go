package relay

import "io"

// RendezvousEstablishedCell acknowledges an ESTABLISH_RENDEZVOUS. Body is
// typically empty; clients MUST ignore any extra bytes (tor rendmid.c sends
// an empty payload).
type RendezvousEstablishedCell struct {
	StreamID uint16
}

func (*RendezvousEstablishedCell) ID() uint8 { return COMMAND_RENDEZVOUS_ESTABLISHED }
func (c *RendezvousEstablishedCell) GetStreamID() uint16 { return c.StreamID }
func (c *RendezvousEstablishedCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *RendezvousEstablishedCell) Encode(w io.Writer) error {
	return nil
}
func (c *RendezvousEstablishedCell) Decode(r io.Reader) error {
	// Client ignores the (typically empty) body.
	return nil
}
