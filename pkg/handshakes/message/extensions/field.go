package extensions

import "bytes"

type Field interface {
	Marshal() []byte
	Unmarshal(*bytes.Reader) error
}
