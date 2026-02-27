package cells

import (
	"bytes"
	"encoding/binary"
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

	// Writing time stamp
	time := make([]byte, 4)
	binary.BigEndian.PutUint32(time, c.Timestamp)
	if _, err := w.Write(time); err != nil {
		return err
	}

	// Writing OtherAddr
	if _, err := w.Write(serializeIp(c.OtherAddr)); err != nil {
		return err
	}
	//Writing MyAdress
	// LEN
	if _, err := w.Write([]byte{uint8(len(c.MyAdress))}); err != nil {
		return err
	}

	for _, v := range c.MyAdress {
		w.Write(serializeIp(v))
	}

	return nil
}

func (c *NetInfoCell) Decode(r io.Reader) error {

	if err := binary.Read(r, binary.BigEndian, &c.Timestamp); err != nil {
		return err
	}
	offst := 4

	c.OtherAddr = unserializeIp(r, &offst)

	totalAddr := make([]byte, 1)
	if _, err := io.ReadFull(r, totalAddr); err != nil {
		return err
	}
	offst += 1

	for range totalAddr[0] {
		c.MyAdress = append(c.MyAdress, unserializeIp(r, &offst))
	}
	_, err := io.CopyN(io.Discard, r, int64(CELL_BODY_LEN-offst))

	return err
}

func unserializeIp(reader io.Reader, offset *int) netip.Addr {

	b := make([]byte, 1)
	_, err := reader.Read(b)
	if err != nil {
		panic(err)
	}
	*offset += 1
	atype := b[0]

	if _, err := io.CopyN(io.Discard, reader, 1); err != nil {
		panic(err)
	}
	*offset += 1

	switch atype {
	case NETINFO_IPV4:
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			panic(err)
		}

		addr, _ := netip.AddrFromSlice(buffer)
		*offset += 4
		return addr

	case NETINFO_IPV6:
		buffer := make([]byte, 16)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			panic(err)
		}

		addr, _ := netip.AddrFromSlice(buffer)
		*offset += 16
		return addr
	}

	return netip.Addr{}
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
