package extensions

import "bytes"

const SUBPROTO byte = 3

type SubprotocolRequest struct {
	ValuesPair map[byte]byte
}

func (sub *SubprotocolRequest) Marshal() []byte {

	var buffer bytes.Buffer
	buffer.Grow(len(sub.ValuesPair) << 1)
	for k, v := range sub.ValuesPair {
		buffer.Write([]byte{k, v})
	}
	return buffer.Bytes()
}

func (sub *SubprotocolRequest) Unmarshal(r *bytes.Reader) error {
	valuesN := r.Size() << 1
	sub.ValuesPair = make(map[byte]byte, valuesN)

	for range valuesN {
		k, err := r.ReadByte()
		if err != nil {
			return err
		}

		v, err := r.ReadByte()
		if err != nil {
			return err
		}

		sub.ValuesPair[k] = v
	}
	return nil
}
