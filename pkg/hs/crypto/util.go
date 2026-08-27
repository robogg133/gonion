package crypto

import (
	"encoding/binary"
	"io"
)

func writePeriods(w io.Writer, periodNum, periodLen uint64) {
	binary.Write(w, binary.BigEndian, periodNum)
	binary.Write(w, binary.BigEndian, periodLen)
}
