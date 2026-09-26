package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
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
	if err := validateBeginTarget(c.Addrport); err != nil {
		return err
	}
	if c.Flags & ^uint32(7) != 0 {
		return fmt.Errorf("relay: reserved BEGIN flags")
	}
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
	body, err := io.ReadAll(io.LimitReader(r, RELAY_BODY_LEN+1))
	if err != nil {
		return err
	}
	n := bytes.IndexByte(body, 0)
	if n < 0 || len(body) > RELAY_BODY_LEN {
		return fmt.Errorf("relay: invalid BEGIN payload")
	}
	c.Addrport, c.Flags = string(body[:n]), 0
	if err := validateBeginTarget(c.Addrport); err != nil {
		return err
	}
	// FLAGS is omitted when zero. Unknown flags and trailing bytes are
	// ignored by receivers (tor-spec 6.2; C Tor begin_cell_parse).
	if len(body)-n-1 >= 4 {
		c.Flags = binary.BigEndian.Uint32(body[n+1:])
	}
	return nil
}

func validateBeginTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	p, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || p == 0 || len(target) > RELAY_BODY_LEN-5 || strings.ContainsAny(host, "\x00\r\n\t /%") {
		return fmt.Errorf("relay: invalid BEGIN target")
	}
	return nil
}
