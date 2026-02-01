package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash"
)

const COMMAND_SENDME uint8 = 5

type SendMeCell struct {
	StreamID uint16

	Sha1ForLastCell [20]byte
	Forward         hash.Hash
}

func (c *SendMeCell) Serialize() []byte {
	var result bytes.Buffer

	result.WriteByte(COMMAND_SENDME)

	result.Write([]byte{0, 0}) // Recognized

	streamID := make([]byte, 2)
	binary.BigEndian.PutUint16(streamID, c.StreamID)
	result.Write(streamID)

	result.Write([]byte{0, 0, 0, 0}) // Digest

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, 23)
	result.Write(length)

	// DATA

	result.WriteByte(1)

	twenty := make([]byte, 2)
	binary.BigEndian.PutUint16(twenty, 20)
	result.Write(twenty)
	result.Write(c.Sha1ForLastCell[:])

	// END

	padding := make([]byte, 509-result.Len())
	rand.Read(padding[4:])
	result.Write(padding)

	buffer := result.Bytes()
	result.Reset()

	c.Forward.Write(buffer)

	copy(buffer[5:9], c.Forward.Sum(nil)[0:4])

	return buffer
}
