package cells

import (
	"bytes"
	"encoding/binary"
)

const COMMAND_DESTROY uint8 = 4

type DestroyCell struct {
	CircuitID uint32

	Reason uint8
}

func (c *DestroyCell) Serialize() []byte {
	var result bytes.Buffer

	circID := make([]byte, 4)
	binary.BigEndian.PutUint32(circID, c.CircuitID)

	result.Write(circID)
	result.WriteByte(COMMAND_DESTROY)
	result.WriteByte(c.Reason)

	for _ = range 509 - result.Len() {
		result.WriteByte(0x00)
	}

	return result.Bytes()
}
