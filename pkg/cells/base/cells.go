package cells

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"git.servidordomal.fun/robogg133/gonion-rewrite/pkg/cells/relay"
)

const CELL_BODY_LEN int = 509

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

type CellCoder struct {
	knownCells map[uint8]func() Cell

	cellBodyLen int

	RelayCoder *relay.RelayCellCoder
}

var AllKnownCells = map[uint8]func() Cell{
	COMMAND_CERTS:        func() Cell { return &CertsCell{} },
	COMMAND_CREATE_FAST:  func() Cell { return &CreateFastCell{} },
	COMMAND_CREATED_FAST: func() Cell { return &CreatedFastCell{} },
	COMMAND_DESTROY:      func() Cell { return &DestroyCell{} },
	COMMAND_NETINFO:      func() Cell { return &NetInfoCell{} },
	COMMAND_RELAY:        func() Cell { return &RelayCell{} },
}

// NewCellCoder can encode and decode cells
func NewCellCoder(knwonCells map[uint8]func() Cell, relayCoder *relay.RelayCellCoder) *CellCoder {
	return &CellCoder{
		knownCells:  knwonCells,
		RelayCoder:  relayCoder,
		cellBodyLen: CELL_BODY_LEN,
	}
}

// ReadCell reads a cell from the reader
func (r *CellCoder) ReadCell(reader io.Reader) (Cell, error) {

	if _, err := io.CopyN(io.Discard, reader, 4); err != nil {
		return nil, err
	}

	cmd := make([]byte, 1)

	if _, err := io.ReadFull(reader, cmd); err != nil {
		return nil, err
	}

	cell := r.knownCells[cmd[0]]()

	if cell.ID() == COMMAND_RELAY {
		cell.(*RelayCell).RelayCoder = r.RelayCoder
	}

	if err := cell.Decode(reader); err != nil {
		return nil, err
	}

	return cell, nil
}

func (r *CellCoder) MarshalCell(cell Cell) ([]byte, error) {
	var a bytes.Buffer
	err := r.WriteCell(cell, &a)
	return a.Bytes(), err
}

func (r *CellCoder) WriteCell(cell Cell, writer io.Writer) error {

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

	for range r.cellBodyLen - buffer.Len() {
		buffer.WriteByte(0)
	}

	_, err := writer.Write(buffer.Bytes())
	return err
}
