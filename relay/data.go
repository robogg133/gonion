package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

const COMMAND_DATA uint8 = 2

type DataCell struct {
	StreamID uint16

	// If you are sending this cell this needs to be the Forward hash otherwise needs to be the backwards
	DigestWriter hash.Hash
	// If you sending this cell this can be empty
	Digest [4]byte

	Payload []byte
}

func (c *DataCell) Serialize() RelayCell {
	var result bytes.Buffer

	result.WriteByte(COMMAND_DATA)
	result.Write([]byte{0, 0})

	streamID := make([]byte, 2)
	binary.BigEndian.PutUint16(streamID, c.StreamID)
	result.Write(streamID)

	result.Write([]byte{0, 0, 0, 0}) // Digest

	payloadLength := make([]byte, 2)
	binary.BigEndian.PutUint16(payloadLength, uint16(len(c.Payload)))
	result.Write(payloadLength)

	result.Write(c.Payload)

	padding := make([]byte, 509-result.Len())
	rand.Read(padding[4:])

	result.Write(padding)

	buffer := result.Bytes()
	result.Reset()

	c.DigestWriter.Write(buffer)
	sum := c.DigestWriter.Sum(nil)

	copy(buffer[5:9], sum[0:4])

	return buffer
}

var ErrRelayEnd = errors.New("data end")

func UnserializeDataCell(b []byte, backwards hash.Hash) ([]byte, error) {
	var c DataCell

	if b[0] != COMMAND_DATA {
		if b[0] == COMMAND_RELAY_END {
			if !bytes.Equal(b[1:3], []byte{0, 0}) {
				return nil, nil
			}
			CheckGenericCell(b, COMMAND_RELAY_END, backwards)
			return nil, ErrRelayEnd
		}

		return nil, fmt.Errorf("invalid cell command")
	}

	if !bytes.Equal(b[1:3], []byte{0, 0}) {
		return nil, fmt.Errorf("the payload is still encrypted")
	}

	c.StreamID = binary.BigEndian.Uint16(b[3:5])

	if !backwardCheck(b, [4]byte(b[5:9]), backwards) {
		return nil, fmt.Errorf("cell digest is not valid")
	}

	length := binary.BigEndian.Uint16(b[9:11])

	payload := make([]byte, length)

	copy(payload, b[11:])

	return payload, nil
}
