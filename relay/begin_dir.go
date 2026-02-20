package relay

import (
	"io"
)

const (
	COMMAND_BEGIN_DIR uint8 = 13
)

type RelayCell []byte

type BeginDir struct {
	StreamID uint16
}

func (*BeginDir) ID() uint8              { return COMMAND_BEGIN_DIR }
func (c *BeginDir) GetStreamID() uint16  { return c.StreamID }
func (c *BeginDir) setStreamID(n uint16) { c.StreamID = n }

func (*BeginDir) Encode(io.Writer) error { return nil }
func (*BeginDir) Decode(io.Reader) error { return nil }
