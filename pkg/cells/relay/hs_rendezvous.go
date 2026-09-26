package relay

import (
	"fmt"
	"io"
)

// Rendezvous1Cell, sent by the service to the rendezvous point to join its
// circuit (rendezvous-protocol §JOIN_REND).
type Rendezvous1Cell struct {
	StreamID      uint16
	Cookie        [cookieLen]byte
	HandshakeInfo []byte
}

func (*Rendezvous1Cell) ID() uint8              { return COMMAND_RENDEZVOUS1 }
func (c *Rendezvous1Cell) GetStreamID() uint16  { return c.StreamID }
func (c *Rendezvous1Cell) SetStreamID(n uint16) { c.StreamID = n }

func (c *Rendezvous1Cell) Encode(w io.Writer) error {
	if _, err := w.Write(c.Cookie[:]); err != nil {
		return err
	}
	_, err := w.Write(c.HandshakeInfo)
	return err
}
func (c *Rendezvous1Cell) Decode(r io.Reader) error {
	if _, err := io.ReadFull(r, c.Cookie[:]); err != nil {
		return err
	}
	var err error
	c.HandshakeInfo, err = io.ReadAll(r)
	return err
}

// Rendezvous2Cell relays the service's handshake reply to the client.
type Rendezvous2Cell struct {
	StreamID      uint16
	HandshakeInfo []byte
}

func (*Rendezvous2Cell) ID() uint8              { return COMMAND_RENDEZVOUS2 }
func (c *Rendezvous2Cell) GetStreamID() uint16  { return c.StreamID }
func (c *Rendezvous2Cell) SetStreamID(n uint16) { c.StreamID = n }

func (c *Rendezvous2Cell) Encode(w io.Writer) error {
	if len(c.HandshakeInfo) != 64 {
		return fmt.Errorf("relay: HS-ntor rendezvous reply must be 64 bytes")
	}
	_, err := w.Write(c.HandshakeInfo)
	return err
}
func (c *Rendezvous2Cell) Decode(r io.Reader) error {
	// C Tor still pads RENDEZVOUS1 to 168 bytes; the relay forwards the
	// padding after stripping the cookie. It is not part of HANDSHAKE_INFO.
	var err error
	c.HandshakeInfo, err = readExact(r, 64)
	return err
}
