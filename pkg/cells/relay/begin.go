package relay

import (
	"bufio"
	"encoding/binary"
	"io"
)

const (
	COMMAND_BEGIN uint8 = 1
)

// BEGIN flags (tor-spec): bit 1 = IPv6 OK, bit 2 = IPv4 not OK, bit 3 = IPv6 preferred.
const (
	BEGIN_FLAG_IPV6_OK        uint32 = 1
	BEGIN_FLAG_IPV4_NOT_OK    uint32 = 2
	BEGIN_FLAG_IPV6_PREFERRED uint32 = 4
)

type BeginCell struct {
	StreamID uint16

	Addrport string
	Flags    uint32
}

func (*BeginCell) ID() uint8              { return COMMAND_BEGIN }
func (c *BeginCell) GetStreamID() uint16  { return c.StreamID }
func (c *BeginCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *BeginCell) Encode(w io.Writer) error {
	if _, err := w.Write(append([]byte(c.Addrport), 0)); err != nil {
		return err
	}
	// tor-spec: "Whenever 0 would be sent for FLAGS, FLAGS is omitted from the
	// message body." The onion-service stream (empty address, flags 0) therefore
	// encodes to just ":<port>\x00".
	if c.Flags == 0 {
		return nil
	}
	return binary.Write(w, binary.BigEndian, c.Flags)
}

func (c *BeginCell) Decode(r io.Reader) error {
	br := bufio.NewReader(r)
	s, err := br.ReadString(0)
	if err != nil {
		return err
	}
	c.Addrport = s
	return binary.Read(br, binary.BigEndian, &c.Flags)
}
