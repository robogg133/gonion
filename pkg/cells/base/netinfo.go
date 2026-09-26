package cells

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
)

const COMMAND_NETINFO uint8 = 8

const (
	NETINFO_IPV4 byte = 0x04
	NETINFO_IPV6 byte = 0x06
)

type NetInfoCell struct {
	CircuitID uint32

	Timestamp uint32       // UNIX Timestamp (should be empty if you aren't a relay)
	OtherAddr netip.Addr   // recipient's address
	MyAdress  []netip.Addr // sender's adress (should be empty if you aren't a relay)
}

func (*NetInfoCell) ID() uint8               { return COMMAND_NETINFO }
func (c *NetInfoCell) GetCircuitID() uint32  { return c.CircuitID }
func (c *NetInfoCell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *NetInfoCell) Encode(w io.Writer) error {
	if !c.OtherAddr.IsValid() || len(c.MyAdress) > 255 {
		return fmt.Errorf("NETINFO: invalid recipient address or address count")
	}
	var payload bytes.Buffer
	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], c.Timestamp)
	payload.Write(timestamp[:])
	payload.Write(serializeIp(c.OtherAddr))
	payload.WriteByte(byte(len(c.MyAdress)))
	for _, addr := range c.MyAdress {
		if !addr.IsValid() {
			return fmt.Errorf("NETINFO: invalid sender address")
		}
		payload.Write(serializeIp(addr))
	}
	if payload.Len() > CELL_BODY_LEN {
		return fmt.Errorf("NETINFO: addresses exceed fixed payload")
	}
	n, err := w.Write(payload.Bytes())
	if err == nil && n != payload.Len() {
		err = io.ErrShortWrite
	}
	return err
}

func (c *NetInfoCell) Decode(r io.Reader) error {
	// Bound parsing even when Decode is called without CellCoder. Read the
	// whole fixed payload first so address lengths cannot cross a cell boundary.
	var body [CELL_BODY_LEN]byte
	if _, err := io.ReadFull(r, body[:]); err != nil {
		return err
	}
	in := bytes.NewReader(body[4:])
	other, err := unserializeIp(in)
	if err != nil {
		return err
	}
	count, err := in.ReadByte()
	if err != nil {
		return err
	}
	var addresses []netip.Addr
	for range count {
		addr, err := unserializeIp(in)
		if err != nil {
			return err
		}
		if addr.IsValid() {
			addresses = append(addresses, addr)
		}
	}
	// tor-spec 4.5 requires ignoring trailing padding and addresses whose
	// type/length pair is not recognized. Commit only a complete parse.
	c.Timestamp = binary.BigEndian.Uint32(body[:4])
	c.OtherAddr, c.MyAdress = other, addresses
	return nil
}

func unserializeIp(reader io.Reader) (netip.Addr, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return netip.Addr{}, err
	}
	var value [255]byte
	b := value[:int(header[1])]
	if _, err := io.ReadFull(reader, b); err != nil {
		return netip.Addr{}, err
	}
	if header[0] == NETINFO_IPV4 && len(b) == 4 || header[0] == NETINFO_IPV6 && len(b) == 16 {
		addr, _ := netip.AddrFromSlice(b)
		return addr, nil
	}
	return netip.Addr{}, nil
}

func serializeIp(ipAddr netip.Addr) []byte {
	var result bytes.Buffer
	if ipAddr.Is4() {
		result.WriteByte(NETINFO_IPV4)
		result.WriteByte(byte(4))
	} else {
		result.WriteByte(NETINFO_IPV6)
		result.WriteByte(byte(16))
	}
	ip, _ := ipAddr.MarshalBinary()
	result.Write(ip)

	return result.Bytes()
}
