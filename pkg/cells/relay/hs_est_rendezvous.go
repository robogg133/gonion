package relay

import "io"

// EstRendezvousCell sets up a rendezvous point (rendezvous-protocol
// §EST_REND_POINT). Wire: RENDEZVOUS_COOKIE(20).
type EstRendezvousCell struct {
	StreamID uint16
	Cookie   [cookieLen]byte
}

func (*EstRendezvousCell) ID() uint8              { return COMMAND_ESTABLISH_RENDEZVOUS }
func (c *EstRendezvousCell) GetStreamID() uint16  { return c.StreamID }
func (c *EstRendezvousCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *EstRendezvousCell) Encode(w io.Writer) error {
	_, err := w.Write(c.Cookie[:])
	return err
}
func (c *EstRendezvousCell) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, c.Cookie[:])
	return err
}