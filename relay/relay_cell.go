package relay

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
)

// All cells must be 514 bytes (on version 4+): 5 bytes for the headers, +11 for internal relay protocol, so the body must be 498 bytes
const RELAY_BODY_LEN = 498

var AllKnownRellayCells map[uint8]Cell = map[uint8]Cell{
	COMMAND_DATA:      &DataCell{},
	COMMAND_CONNECTED: &ConnectedCell{},
	COMMAND_SENDME:    &SendMeCell{},
	COMMAND_RELAY_END: &RelayEndCell{},
	COMMAND_BEGIN_DIR: &BeginDir{},
}

type Cell interface {
	ID() uint8

	GetStreamID() uint16
	SetStreamID(uint16)

	Decode(r io.Reader) error
	Encode(w io.Writer) error
}

type RelayCellConstructor struct {
	backwardsHash   hash.Hash
	backwardsStream cipher.Stream

	forwardsHash   hash.Hash
	forwardsStream cipher.Stream
}

func NewDataCellConstructor(bh, fh hash.Hash, bs, fs cipher.Stream) RelayCellConstructor {
	return RelayCellConstructor{
		backwardsHash:   bh,
		backwardsStream: bs,

		forwardsHash:   fh,
		forwardsStream: fs,
	}
}

// Marshal Encodes the given cell, aply all relay headers, apply digest to the header and returns []byte with encrypted data
func (d *RelayCellConstructor) Marshal(c Cell) ([]byte, error) {
	var buffer bytes.Buffer

	// Command pos[0]
	if err := buffer.WriteByte(c.ID()); err != nil {
		return nil, err
	}

	// Recognized pos[1:3]
	if _, err := buffer.Write([]byte{0, 0}); err != nil {
		return nil, err
	}

	// StreamID pos[3:5]
	if err := binary.Write(&buffer, binary.BigEndian, c.GetStreamID()); err != nil {
		return nil, err
	}

	// Digest pos[5:9]
	if _, err := buffer.Write([]byte{0, 0, 0, 0}); err != nil {
		return nil, err
	}

	var payload bytes.Buffer

	if err := c.Encode(&payload); err != nil {
		return nil, err
	}

	pLenght := payload.Len()
	if pLenght > RELAY_BODY_LEN {
		return nil, fmt.Errorf("too big payload max size: %d, actual size: %d", RELAY_BODY_LEN, pLenght)
	}
	// Writing payload length without padding
	// This ends with the header section
	payloadLenght := make([]byte, 2)
	binary.BigEndian.PutUint16(payloadLenght, uint16(pLenght))
	if _, err := buffer.Write(payloadLenght); err != nil {
		return nil, err
	}

	applyPadding(&payload)

	if _, err := buffer.Write(payload.Bytes()); err != nil {
		return nil, err
	}
	payload.Reset()

	b := buffer.Bytes()
	buffer.Reset()

	_, err := d.forwardsHash.Write(b)
	if err != nil {
		return nil, err
	}

	digest := d.forwardsHash.Sum(nil)
	copy(b[5:9], digest[0:4]) // Copy the firsts 4 bytes from the sum, to the Digest

	dst := make([]byte, 509) // 509 = 498 (Payload length) + 11 (Headers length)
	d.forwardsStream.XORKeyStream(dst, b)
	b = nil
	return dst, nil
}

func (d *RelayCellConstructor) Unmarshal(b []byte) (Cell, error) {

	plain := make([]byte, len(b))

	d.backwardsStream.XORKeyStream(plain, b)
	b = nil

	// [1:3] Recognized, must be 0
	// If the recognized is not 0, something is wrong, the data is still encrypted
	if !bytes.Equal(plain[1:3], []byte{0, 0}) {
		return nil, fmt.Errorf("recognized is not 0")
	}

	c := AllKnownRellayCells[plain[0]]

	// StreamID [3:5]
	c.SetStreamID(binary.BigEndian.Uint16(plain[3:5]))

	if err := d.backwardCheck(plain); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint16(plain[9:11])

	reader := bytes.NewReader(plain[11 : payloadLen+11])

	return c, c.Decode(reader)
}

func applyPadding(buffer *bytes.Buffer) error {

	paddingNeed := RELAY_BODY_LEN - buffer.Len()

	if paddingNeed <= 4 {
		for range paddingNeed {
			if err := buffer.WriteByte(0); err != nil {
				return err
			}
		}
		return nil
	}

	if _, err := buffer.Write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}

	paddingNeed = paddingNeed - 4

	padding := make([]byte, paddingNeed)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return err
	}

	_, err := buffer.Write(padding)

	return err
}

func (d *RelayCellConstructor) backwardCheck(b []byte) error {
	// [5:9] Digest position (4 bytes)

	// Saving the original value
	originalD := make([]byte, 4)
	copy(originalD, b[5:9])

	// Replacing the original value with 0's
	copy(b[5:9], []byte{0, 0, 0, 0})

	d.backwardsHash.Write(b)
	sum := d.backwardsHash.Sum(nil)

	if !bytes.Equal(originalD[:], sum[0:4]) {
		return fmt.Errorf("error doing backward check, expected result: (%v), but got: (%v)", originalD, sum[0:4])
	}

	return nil
}
