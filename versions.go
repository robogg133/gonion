package gonion

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/robogg133/gonion/connection/cells"
)

func negotiateVersion(r io.Reader, w io.Writer) (uint16, error) {
	versionsCell := &cells.VersionCell{
		CircuitID: 0,
		Versions:  []uint16{4, 5},
	}

	w.Write(versionsCell.Serialize())

	initialBuffer := make([]byte, 5)
	n, err := r.Read(initialBuffer)
	if err != nil {
		return 0, err
	}
	if n != 5 {
		return 0, fmt.Errorf("did not read 5 bytes from connection")
	}

	if uint8(initialBuffer[2]) != cells.COMMAND_VERSIONS {
		return 0, fmt.Errorf("invalid version (%d) cell: invalid command: %d", cells.COMMAND_VERSIONS, uint8(initialBuffer[3]))
	}

	length := binary.BigEndian.Uint16(initialBuffer[3:5])

	versions := make([]byte, 5+length)
	if _, err := r.Read(versions[5:]); err != nil {
		return 0, err
	}

	copy(versions, initialBuffer)

	serverVersions, err := cells.UnserializeVersionCell(versions)
	if err != nil {
		return 0, err
	}

	if slices.Contains(serverVersions.Versions, 5) {
		return 5, nil
	} else if slices.Contains(serverVersions.Versions, 4) {
		return 4, nil
	}

	return 0, fmt.Errorf("no version match with server")
}
