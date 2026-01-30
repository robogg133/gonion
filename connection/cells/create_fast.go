package cells

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	COMMAND_CREATE_FAST  uint8 = 5
	COMMAND_CREATED_FAST uint8 = 6
)

type CreateFastCell struct {
	CircuitID uint32
	X         [20]byte // X is just 20 random bytes
}

type CreatedFastCell struct {
	CircuitID uint32

	Y  [20]byte
	KH [20]byte
}

func (cell *CreateFastCell) Serialize() []byte {
	var result bytes.Buffer

	circID := make([]byte, 4)

	binary.BigEndian.PutUint32(circID, cell.CircuitID)

	result.Write(circID)
	result.WriteByte(COMMAND_CREATE_FAST)
	result.Write(cell.X[:])

	for _ = range 514 - result.Len() {
		result.WriteByte(0x00)
	}

	return result.Bytes()
}

func UnserializeCreatedFast(b []byte) (*CreatedFastCell, error) {
	var cell CreatedFastCell

	cell.CircuitID = binary.BigEndian.Uint32(b[0:4])

	if len(b) != 514 {
		return nil, fmt.Errorf("created_fast with wrong length != 514")
	}

	if uint8(b[4]) != COMMAND_CREATED_FAST {
		return nil, fmt.Errorf("invalid created_fast (%d) cell: invalid command: %d", COMMAND_CREATED_FAST, uint8(b[4]))
	}

	cell.Y = [20]byte(b[5:25])

	cell.KH = [20]byte(b[25:45])

	return &cell, nil
}
