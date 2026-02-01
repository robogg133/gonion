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

func (c *RelayCell) Serialize(stream cipher.Stream) []byte {
	var result bytes.Buffer

	circID := make([]byte, 4)

	binary.BigEndian.PutUint32(circID, c.CircuitID)

	result.Write(circID)
	result.WriteByte(COMMAND_RELAY)

	payload := make([]byte, 509)
	stream.XORKeyStream(payload, c.RelayCell)

	result.Write(payload)

	return result.Bytes()
}

func ReadDataCell(b []byte, stream cipher.Stream, dig hash.Hash) (*RelayCell, error) {
	var c RelayCell

	c.CircuitID = binary.BigEndian.Uint32(b[0:4])

	if b[4] != COMMAND_RELAY {
		fmt.Println(b)
		return nil, fmt.Errorf("invalid cell command")
	}

	payload := b[5:]

	stream.XORKeyStream(payload, payload)

	var err error
	c.RelayCell, err = relay.UnserializeDataCell(payload, dig)
	return &c, err
}

func RelayCheckIfConnected(b []byte, cip *cipher.Stream, dig hash.Hash) error {

	if b[4] != COMMAND_RELAY {
		return fmt.Errorf("invalid cell command")
	}

	payload := b[5:]

	stream := *cip

	res := make([]byte, len(payload))
	stream.XORKeyStream(res, payload)

	err := relay.CheckGenericCell(res, relay.COMMAND_CONNECTED, dig)

	return err
}
