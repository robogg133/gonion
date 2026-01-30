package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
)

type GenericCell struct {
	StreamID uint16
}

// CheckGenericCell is mean to be used with cells that does not have paylods inside
func CheckGenericCell(b []byte, cellCommand uint8, backwards *hash.Hash) error {
	var c GenericCell

	if b[0] != cellCommand {
		return fmt.Errorf("given cell is not of the type given")
	}

	if !bytes.Equal(b[1:3], []byte{0, 0}) {
		return fmt.Errorf("the payload is still encrypted")
	}

	c.StreamID = binary.BigEndian.Uint16(b[3:5])

	if !backwardCheck(b, [4]byte(b[5:9]), backwards) {
		return fmt.Errorf("cell digest is not valid")
	}
	return nil
}

func RecognizeRelayCommand(b []byte) uint8 { return b[0] }

// isGeneric returns true if the cell don't have data on it, otherwise returns false
func isGeneric(i uint8) bool {
	switch i {
	case COMMAND_CONNECTED:
		return true
	case COMMAND_RELAY_END:
		return true
	}
	return false
}

func backwardCheck(b []byte, originalDigest [4]byte, backwards *hash.Hash) bool {
	copy(b[5:9], []byte{0, 0, 0, 0})

	digest := *backwards

	digest.Write(b)
	sum := digest.Sum(nil)

	if !bytes.Equal(originalDigest[:], sum[0:4]) {
		return false
	}

	return true
}
