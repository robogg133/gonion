package relay

import (
	"io"
)

const (
	COMMAND_BEGIN_DIR uint8 = 13
)

type BeginDirCell struct {
	StreamID uint16
}

func (*BeginDirCell) ID() uint8              { return COMMAND_BEGIN_DIR }
func (c *BeginDirCell) GetStreamID() uint16  { return c.StreamID }
func (c *BeginDirCell) SetStreamID(n uint16) { c.StreamID = n }

func (*BeginDirCell) Encode(io.Writer) error { return nil }
func (*BeginDirCell) Decode(io.Reader) error { return nil }
