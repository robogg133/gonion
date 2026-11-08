package shared

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// CIRCUIT_ID_MAX_RETRIES bounds collision/zero retries for one allocation.
	CIRCUIT_ID_MAX_RETRIES = 128

	// MaxCircIDAttempts is the same bound under an exported name for callers
	// that report allocation exhaustion.
	MaxCircIDAttempts = CIRCUIT_ID_MAX_RETRIES
)

// MSB sets the high bit required for a 4-byte CircID (tor-spec 3).
func MSB(n uint32) uint32 {
	n |= 0x80000000
	return n
}

// RandomCircID draws a fresh CircID from r using the bits allowed by the
// negotiated link version. Link version 4 and later use four bytes with the
// most significant bit forced to one. Link versions 2 and 3 use two bytes.
// The caller must still reject zero (possible only in the two-byte form) and
// check the circuit registry for collisions.
func RandomCircID(r io.Reader, linkVersion uint16) (uint32, error) {
	if r == nil {
		r = rand.Reader
	}
	switch {
	case linkVersion >= 4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		return MSB(binary.BigEndian.Uint32(b[:])), nil
	case linkVersion >= 2:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		return uint32(binary.BigEndian.Uint16(b[:])), nil
	default:
		return 0, fmt.Errorf("unsupported link version %d for circuit id", linkVersion)
	}
}
