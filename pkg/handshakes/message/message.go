package message

import (
	"bytes"
	"errors"
	"io"

	"github.com/robogg133/gonion/pkg/handshakes/message/extensions"
)

type Message struct {
	Type  uint8
	Field extensions.Field
}

type TranslationTable map[uint8]func() extensions.Field

func (msg *Message) Marshal() []byte {
	field := msg.Field.Marshal()
	return append([]byte{msg.Type, uint8(len(field))}, field...)
}

func (msg *Message) Unmarshal(r io.Reader, tb TranslationTable) error {

	bBuff := make([]byte, 1)
	_, err := r.Read(bBuff)
	if err != nil {
		return err
	}
	msg.Type = bBuff[0]

	_, err = r.Read(bBuff)
	if err != nil {
		return err
	}

	field := make([]byte, bBuff[0])

	if _, err := r.Read(field); err != nil {
		return err
	}

	fn, ok := tb[msg.Type]
	if !ok {
		return errors.New("message unmarshal: can't find id in translation table")
	}

	msg.Field = fn()
	return msg.Field.Unmarshal(bytes.NewReader(field))
}
