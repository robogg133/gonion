package cells

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/robogg133/gonion/relay"
)

const COMMAND_RELAY uint8 = 3

type RelayCell struct {
	CircuitID uint32

	relay.RelayCell
}

func (c *RelayCell) Serialize(cip *cipher.Stream) []byte {
	var result bytes.Buffer

	circID := make([]byte, 4)

	binary.BigEndian.PutUint32(circID, c.CircuitID)

	result.Write(circID)
	result.WriteByte(COMMAND_RELAY)

	stream := *cip

	payload := make([]byte, 509)
	stream.XORKeyStream(payload, c.RelayCell)

	result.Write(payload)

	return result.Bytes()
}

func RelayCheckIfConnected(b []byte, cip *cipher.Stream, dig *hash.Hash) error {

	if b[4] != COMMAND_RELAY {
		return fmt.Errorf("invalid cell command")
	}

	payload := b[5:]

	stream := *cip
	fmt.Println(payload)
	res := make([]byte, len(payload))
	stream.XORKeyStream(res, payload)
	fmt.Println(res)

	err := relay.CheckGenericCell(res, relay.COMMAND_CONNECTED, dig)

	return err
}
