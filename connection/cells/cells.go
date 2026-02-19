package cells

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const CELL_BODY_LEN = 509

type Cell interface {
	ID() uint8

	GetCircuitID() uint32
	setCircuitID(uint32)

	Decode(r io.Reader) error
	Encode(w io.Writer) error
}

var (
	ErrInvalidCircID    = errors.New("invalid circuit id expected: %s found %s")
	ErrUnknownCommandID = errors.New("unknown command id")
)

type CellTranslator struct {
	circIDLength uint8
	reader       io.Reader
	writer       io.Writer
	knownCells   map[uint8]Cell
}

var AllKnownCells map[uint8]Cell = map[uint8]Cell{
	COMMAND_CERTS:        &CertsCell{},
	COMMAND_CREATE_FAST:  &CertsCell{},
	COMMAND_CREATED_FAST: &CreatedFastCell{},
	COMMAND_DESTROY:      &DestroyCell{},
	COMMAND_NETINFO:      &NetInfoCell{},
}

func NewCellTranslator(r io.Reader, w io.Writer, circIDLen uint8, knwonCells map[uint8]Cell) CellTranslator {
	return CellTranslator{
		reader:       r,
		writer:       w,
		circIDLength: circIDLen,
		knownCells:   knwonCells,
	}
}

func (r *CellTranslator) ReadCell() (Cell, error) {

	cID := make([]byte, r.circIDLength)

	if _, err := io.ReadFull(r.reader, cID); err != nil {
		return nil, err
	}

	circuitID := binary.BigEndian.Uint32(cID)

	cmd := make([]byte, 1)

	if _, err := io.ReadFull(r.reader, cmd); err != nil {
		return nil, err
	}

	cell, exists := r.knownCells[cmd[0]]
	if !exists {
		return nil, ErrUnknownCommandID
	}

	cell.setCircuitID(circuitID)
	err := cell.Decode(r.reader)
	fmt.Println("finish him")
	return cell, err
}

func (r *CellTranslator) WriteCell(cell Cell) error {

	cID := make([]byte, r.circIDLength)

	switch r.circIDLength {
	case 2:
		n := uint16(cell.GetCircuitID())
		binary.BigEndian.PutUint16(cID, n)
	case 4:
		binary.BigEndian.PutUint32(cID, cell.GetCircuitID())
	}

	if _, err := r.writer.Write(cID); err != nil {
		return err
	}

	if _, err := r.writer.Write([]byte{cell.ID()}); err != nil {
		return err
	}

	var buffer bytes.Buffer
	if err := cell.Encode(&buffer); err != nil {
		return err
	}

	for _ = range CELL_BODY_LEN - buffer.Len() {
		buffer.WriteByte(0x00)
	}

	_, err := r.writer.Write(buffer.Bytes())
	return err
}
