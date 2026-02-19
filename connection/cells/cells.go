package cells

import (
	"errors"
	"io"
)

type Cell interface {
	ID() uint8

	Decode(r io.Reader) error
	Encode(w io.Writer) error
}

var ErrInvalidCircID = errors.New("invalid circuit id expected: %s found %s")
