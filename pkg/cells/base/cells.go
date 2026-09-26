package cells

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	knownCells  map[uint8]func() Cell
	cellBodyLen int
}

var AllKnownCells = map[uint8]func() Cell{
	COMMAND_RELAY:        func() Cell { return &RelayCell{} },
	COMMAND_DESTROY:      func() Cell { return &DestroyCell{} },
	COMMAND_CREATE_FAST:  func() Cell { return &CreateFastCell{} },
	COMMAND_CREATED_FAST: func() Cell { return &CreatedFastCell{} },
	COMMAND_NETINFO:      func() Cell { return &NetInfoCell{} },

	COMMAND_RELAY_EARLY: func() Cell { return &RelayEarlyCell{C: &RelayCell{}} },
	COMMAND_CREATE2:     func() Cell { return &Create2Cell{} },
	COMMAND_CREATED2:    func() Cell { return &Created2Cell{} },

	COMMAND_CERTS: func() Cell { return &CertsCell{} },
}

// NewCellCoder can encode and decode link cells.
func NewCellCoder(knownCells map[uint8]func() Cell) *CellCoder {
	return &CellCoder{
		knownCells:  knownCells,
		cellBodyLen: CELL_BODY_LEN,
	}
}

// ReadFrame consumes exactly one cell, including unknown commands. Passing
// version 3 is appropriate before the initial VERSIONS exchange (tor-spec 3).
func ReadFrame(reader io.Reader, version uint16) ([]byte, error) {
	if version < 1 || version > 5 {
		return nil, fmt.Errorf("unsupported link version %d", version)
	}
	idLen := 2
	if version >= 4 {
		idLen = 4
	}
	header := make([]byte, idLen+1, idLen+3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	cmd := header[idLen]
	length := CELL_BODY_LEN
	if version >= 2 && cmd == COMMAND_VERSIONS || version >= 3 && cmd >= 128 {
		header = header[:idLen+3]
		if _, err := io.ReadFull(reader, header[idLen+1:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(header[idLen+1:]))
	}
	frame := make([]byte, len(header)+length)
	copy(frame, header)
	_, err := io.ReadFull(reader, frame[len(header):])
	return frame, err
}

// ReadCell decodes a complete post-negotiation v4/v5 frame. Decode methods only
// see their own payload, so a malformed parser cannot consume the next frame.
func (r *CellCoder) ReadCell(reader io.Reader) (Cell, error) {
	frame, err := ReadFrame(reader, 4)
	if err != nil {
		return nil, err
	}
	cmd := frame[4]
	factory, ok := r.knownCells[cmd]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownCommandID, cmd)
	}
	cell := factory()
	cell.SetCircuitID(binary.BigEndian.Uint32(frame[:4]))
	offset := 5
	if cmd == COMMAND_VERSIONS || cmd >= 128 {
		offset = 7
	}
	if err := cell.Decode(bytes.NewReader(frame[offset:])); err != nil {
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
	var payload bytes.Buffer
	if err := cell.Encode(&payload); err != nil {
		return err
	}
	length, headerLen := r.cellBodyLen, 5
	if cell.ID() == COMMAND_VERSIONS || cell.ID() >= 128 {
		length, headerLen = payload.Len(), 7
		if length > 65535 {
			return fmt.Errorf("variable cell payload too large")
		}
	} else if payload.Len() > length {
		return fmt.Errorf("fixed cell payload too large")
	}
	frame := make([]byte, headerLen+length)
	binary.BigEndian.PutUint32(frame, cell.GetCircuitID())
	frame[4] = cell.ID()
	if headerLen == 7 {
		binary.BigEndian.PutUint16(frame[5:], uint16(length))
	}
	copy(frame[headerLen:], payload.Bytes())
	n, err := writer.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}
