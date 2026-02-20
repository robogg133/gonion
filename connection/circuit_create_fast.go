package connection

import (
	"crypto/rand"

	"github.com/robogg133/gonion/connection/cells"
)

func (t *TORConnection) SendCreateFast() ([20]byte, error) {

	randomBytes := make([]byte, 20)

	if _, err := rand.Read(randomBytes); err != nil {
		return [20]byte{}, err
	}

	x := [20]byte(randomBytes)

	cell := cells.CreateFastCell{
		CircuitID: t.CircuitID,
		X:         x,
	}

	err := t.Translator.WriteCell(&cell)

	return x, err
}

func (t *TORConnection) ReadCreatedFast() (*cells.CreatedFastCell, error) {

	c, err := t.Translator.ReadCell()
	if err != nil {
		return nil, err
	}

	return c.(*cells.CreatedFastCell), nil
}
