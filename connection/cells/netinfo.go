package cells

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
)

const COMMAND_NETINFO uint8 = 8

const (
	NETINFO_IPV4 byte = 0x04
	NETINFO_IPV6 byte = 0x06
)

type NetInfoCell struct {
	CircuitID uint32

	Timestamp uint32       // UNIX Timestamp (should be empty if you aren't a node)
	OtherAddr netip.Addr   // recipient's address
	MyAdress  []netip.Addr // sender's adress (should be empty if you aren't a node)
}

func (cell *NetInfoCell) Serialize() []byte {
	var result bytes.Buffer

	circID := make([]byte, 4)
	binary.BigEndian.PutUint32(circID, cell.CircuitID)

	result.Write(circID)
	result.WriteByte(COMMAND_NETINFO)

	time := make([]byte, 4)
	binary.BigEndian.PutUint32(time, cell.Timestamp)
	result.Write(time)

	result.Write(serializeIp(cell.OtherAddr))

	result.WriteByte(uint8(len(cell.MyAdress)))

	for _, v := range cell.MyAdress {
		result.Write(serializeIp(v))
	}

	for _ = range 514 - result.Len() {
		result.WriteByte(0x00)
	}
	return result.Bytes()
}

func UnserializeNetInfo(b []byte) (*NetInfoCell, error) {
	var cell NetInfoCell

	if len(b) != 514 {
		return nil, fmt.Errorf("net info with wrong length != 514")
	}

	if uint8(b[4]) != COMMAND_NETINFO {
		return nil, fmt.Errorf("invalid netinfo (%d) cell: invalid command: %d", COMMAND_NETINFO, uint8(b[4]))
	}

	cell.CircuitID = binary.BigEndian.Uint32(b[0:4])

	cell.Timestamp = binary.BigEndian.Uint32(b[5:9])

	reader := bytes.NewReader(b[9:])

	cell.OtherAddr = unserializeIp(reader)

	totalAddr, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	for _ = range uint8(totalAddr) {
		cell.MyAdress = append(cell.MyAdress, unserializeIp(reader))
	}

	return &cell, nil
}

func unserializeIp(reader *bytes.Reader) netip.Addr {

	atype, _ := reader.ReadByte()
	reader.ReadByte()

	switch atype {
	case NETINFO_IPV4:
		buffer := make([]byte, 4)
		reader.Read(buffer)

		addr, _ := netip.AddrFromSlice(buffer)
		return addr

	case NETINFO_IPV6:
		buffer := make([]byte, 16)
		reader.Read(buffer)

		addr, _ := netip.AddrFromSlice(buffer)
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
