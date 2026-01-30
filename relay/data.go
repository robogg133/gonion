package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash"
)

const COMMAND_DATA uint8 = 2

type DataCell struct {
	StreamID uint16

	// If you are sending this cell this needs to be the Forward hash otherwise needs to be the backwards
	DigestWriter *hash.Hash
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

	w := *c.DigestWriter

	w.Write(buffer)
	sum := w.Sum(nil)

	copy(buffer[5:9], sum[0:4])

	return buffer
}
