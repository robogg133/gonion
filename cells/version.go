package cells

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const COMMAND_VERSIONS uint8 = 7

type VersionCell struct {
	CircuitID uint16
	Versions  []uint16
}

func (cell *VersionCell) Serialize() []byte {

	var result bytes.Buffer

	circuitBuffer := make([]byte, 2)
	binary.BigEndian.PutUint16(circuitBuffer, cell.CircuitID)

	result.Write(circuitBuffer)
	result.WriteByte(byte(COMMAND_VERSIONS))

	var payload bytes.Buffer

	for _, v := range cell.Versions {
		buffer := make([]byte, 2)
		binary.BigEndian.PutUint16(buffer, v)
		payload.Write(buffer)
	}

	lenght := make([]byte, 2)
	binary.BigEndian.PutUint16(lenght, uint16(payload.Len()))

	result.Write(lenght)
	result.Write(payload.Bytes())
	payload.Reset()

	return result.Bytes()
}

func UnserializeVersionCell(b []byte) (*VersionCell, error) {

	var cell VersionCell

	if len(b) < 7 { // circId (2) + command (1) + lenght (2) + atleast one version (2) = 7
		return nil, fmt.Errorf("invalid version cell: total length less than 7")
	}

	if uint8(b[2]) != COMMAND_VERSIONS {
		return nil, fmt.Errorf("invalid version cell: invalid command: %d", uint8(b[2]))
	}

	cell.CircuitID = binary.BigEndian.Uint16(b[0:2])
	if cell.CircuitID != 0 {
		return nil, fmt.Errorf("circuitID is not 0, circuitID : %d", cell.CircuitID)
	}

	length := binary.BigEndian.Uint16(b[3:5])

	cell.Versions = make([]uint16, length/2)

	reader := bytes.NewBuffer(b[5 : 5+length])

	for _ = range length / 2 {
		buffer := make([]byte, 2)
		reader.Read(buffer)

		cell.Versions = append(cell.Versions, binary.BigEndian.Uint16(buffer))
	}

	return &cell, nil
}
