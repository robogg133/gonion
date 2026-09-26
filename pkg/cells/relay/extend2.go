package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/robogg133/gonion/pkg/handshakes"
	"github.com/robogg133/gonion/pkg/lspec"
)

const COMMAND_EXTEND2 uint8 = 14

type Extend2Cell struct {
	StreamID  uint16
	Lspecs    []lspec.Lspec
	HType     uint16
	Handshake handshakes.Handshake
}

func (*Extend2Cell) ID() uint8              { return COMMAND_EXTEND2 }
func (c *Extend2Cell) GetStreamID() uint16  { return c.StreamID }
func (c *Extend2Cell) SetStreamID(n uint16) { c.StreamID = n }

func (c *Extend2Cell) Encode(w io.Writer) error {
	if c.StreamID != 0 || len(c.Lspecs) == 0 || len(c.Lspecs) > 255 || c.Handshake == nil {
		return fmt.Errorf("invalid EXTEND2 fields")
	}
	var payload bytes.Buffer
	payload.WriteByte(byte(len(c.Lspecs)))
	// rend-spec-v3 2.5.2.2: retain descriptor/RP specifiers and their order.
	for _, spec := range c.Lspecs {
		if err := spec.Write(&payload); err != nil {
			return err
		}
	}
	var handshake bytes.Buffer
	if err := c.Handshake.Encode(&handshake); err != nil {
		return err
	}
	if handshake.Len() > 65535 || payload.Len()+4+handshake.Len() > RELAY_BODY_LEN {
		return fmt.Errorf("EXTEND2 payload too large")
	}
	binary.Write(&payload, binary.BigEndian, c.HType)
	binary.Write(&payload, binary.BigEndian, uint16(handshake.Len()))
	payload.Write(handshake.Bytes())
	_, err := w.Write(payload.Bytes())
	return err
}

func (*Extend2Cell) Decode(r io.Reader) error {
	return fmt.Errorf("received EXTEND2 on a client circuit")
}
