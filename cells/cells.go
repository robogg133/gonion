package cells

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/robogg133/gonion/relay"
)

const CELL_BODY_LEN = 509

type Cell interface {
	ID() uint8

	GetCircuitID() uint32
	SetCircuitID(uint32)

	Decode(r io.Reader) error
	Encode(w io.Writer) error
}

var (
	ErrInvalidCircID    = errors.New("invalid circuit id expected: %s found %s")
	ErrUnknownCommandID = errors.New("unknown command id")
)

type CellTranslator struct {
	knownCells map[uint8]func() Cell

	Constructor relay.RelayCellConstructor
}

var AllKnownCells = map[uint8]func() Cell{
	COMMAND_CERTS:        func() Cell { return &CertsCell{} },
	COMMAND_CREATE_FAST:  func() Cell { return &CreateFastCell{} },
	COMMAND_CREATED_FAST: func() Cell { return &CreatedFastCell{} },
	COMMAND_DESTROY:      func() Cell { return &DestroyCell{} },
	COMMAND_NETINFO:      func() Cell { return &NetInfoCell{} },
	COMMAND_RELAY:        func() Cell { return &RelayCell{} },
}

// NewCellTranslator can encode and decode cells
func NewCellTranslator(knwonCells map[uint8]func() Cell, constructor relay.RelayCellConstructor) CellTranslator {
	return CellTranslator{
		knownCells:  knwonCells,
		Constructor: constructor,
	}
}

// ReadCell reads a cell from the reader
func (r *CellTranslator) ReadCell(reader io.Reader) (Cell, error) {

	cID := make([]byte, 4)
	if _, err := io.ReadFull(reader, cID); err != nil {
		return nil, err
	}
	circuitID := binary.BigEndian.Uint32(cID)

	cmd := make([]byte, 1)

	if _, err := io.ReadFull(reader, cmd); err != nil {
		return nil, err
	}

	cell := r.knownCells[cmd[0]]()

	cell.SetCircuitID(circuitID)

	if cell.ID() == COMMAND_RELAY {
		cell.(*RelayCell).Constructor = &r.Constructor
	}

	if err := cell.Decode(reader); err != nil {
		return nil, err
	}

	return cell, nil
}

func (r *CellTranslator) WriteCellBytes(cell Cell) ([]byte, error) {
	var a bytes.Buffer
	err := r.WriteCell(cell, &a)
	return a.Bytes(), err
}

func (r *CellTranslator) WriteCell(cell Cell, writer io.Writer) error {

	circID := make([]byte, 4)
	binary.BigEndian.PutUint32(circID, cell.GetCircuitID())

	if _, err := writer.Write(circID); err != nil {
		return err
	}

	if _, err := writer.Write([]byte{cell.ID()}); err != nil {
		return err
	}

	var buffer bytes.Buffer
	if err := cell.Encode(&buffer); err != nil {
		return err
	}

	for _ = range CELL_BODY_LEN - buffer.Len() {
		buffer.WriteByte(0)
	}

	_, err := writer.Write(buffer.Bytes())
	return err
}
