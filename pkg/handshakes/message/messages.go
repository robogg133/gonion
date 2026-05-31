package message

import (
	"bytes"
	"fmt"
	"io"
	"sort"
)

type Messages struct {
	msgs []Message
}

func (msgs *Messages) Marshal() []byte {
	var buffer bytes.Buffer

	buffer.WriteByte(uint8(len(msgs.msgs)))

	msgs.msgs = removeEqual(msgs.msgs)
	sort.Slice(msgs.msgs, func(i, j int) bool {
		return msgs.msgs[i].Type < msgs.msgs[j].Type
	})
	for _, msg := range msgs.msgs {
		buffer.Write(msg.Marshal())
	}
	return buffer.Bytes()
}

func Unmarshal(r io.Reader, tb TranslationTable) (*Messages, error) {
	msgs := new(Messages)

	n := make([]byte, 1)
	r.Read(n)
	NExtensions := n[0]

	exists := make(map[uint8]struct{})
	var last uint8
	for range NExtensions {
		var msg Message

		if err := msg.Unmarshal(r, tb); err != nil {
			return nil, err
		}
		if _, ok := exists[msg.Type]; ok {
			return nil, fmt.Errorf("messages unmarshal: can not have 2 extensions with same type in messages: %d", msg.Type)
		}
		if last > msg.Type {
			return nil, fmt.Errorf("messages unmarshal: messages need to be sorted by type; last type: %d, type now: %d", last, msg.Type)
		}

		msgs.msgs = append(msgs.msgs, msg)
		last = msg.Type
	}

	return msgs, nil
}

func removeEqual(msgs []Message) []Message {
	seen := make(map[uint8]struct{})
	n := 0
	for _, m := range msgs {
		if _, ok := seen[m.Type]; !ok {
			seen[m.Type] = struct{}{}
			msgs[n] = m
			n++
		}
	}
	var zero Message
	for i := n; i < len(msgs); i++ {
		msgs[i] = zero
	}
	return msgs[:n]
}
