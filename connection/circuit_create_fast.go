package connection

import (
	"crypto/rand"
	"fmt"

	"github.com/robogg133/gonion/connection/cells"
)

func (t *TORConnection) SendCreateFast() ([20]byte, error) {

	randomBytes := make([]byte, 20)

	if _, err := rand.Read(randomBytes); err != nil {
		return [20]byte{}, err
	}

	var msbCircID uint32 = 1
	msbCircID |= 0x80000000

	t.CircuitID = msbCircID

	x := [20]byte(randomBytes)

	cell := cells.CreateFastCell{
		CircuitID: msbCircID,
		X:         x,
	}

	_, err := t.Conn.Write(cell.Serialize())

	return x, err
}

func (t *TORConnection) ReadCreatedFast() (*cells.CreatedFastCell, error) {

	cellSerial := make([]byte, 514)

	n, err := t.Conn.Read(cellSerial)
	if err != nil {
		return nil, err
	}
	if n != 514 {
		return nil, fmt.Errorf("cell length is not 514")
	}

	return cells.UnserializeCreatedFast(cellSerial)
}
