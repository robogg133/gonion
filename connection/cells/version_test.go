package cells_test

import (
	"fmt"
	"testing"

	"github.com/robogg133/gonion/connection/cells"
)

func TestVersions(t *testing.T) {
	cell := cells.VersionCell{
		CircuitID: 0,
		Versions:  []uint16{4, 5},
	}

	fmt.Println(cell.Serialize())
}
