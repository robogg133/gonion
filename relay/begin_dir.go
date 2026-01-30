package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash"
)

const (
	COMMAND_BEGIN_DIR uint8 = 13
)

type RelayCell []byte

type BeginDir struct {
	StreamID uint16

	DigestWriter *hash.Hash
}

func (c *BeginDir) Serialize() RelayCell {

	var result bytes.Buffer

	result.WriteByte(COMMAND_BEGIN_DIR)
	result.Write([]byte{0, 0}) //Recognized

	streamID := make([]byte, 2)
	binary.BigEndian.PutUint16(streamID, c.StreamID)
	result.Write(streamID)

	result.Write([]byte{0, 0, 0, 0}) // Digest 5:9

	result.Write([]byte{0, 0}) // Length

	padding := make([]byte, 498)
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
