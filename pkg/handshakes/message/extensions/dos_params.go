package extensions

import "bytes"

const DOS_PARAMS byte = 1

type DoSParams struct {
	Params map[byte][8]byte
}

func (d *DoSParams) Marshal() []byte {
	NParams := len(d.Params)
	totalLen := NParams*8 + NParams + 1

	var buffer bytes.Buffer
	buffer.Grow(totalLen)

	buffer.WriteByte(byte(NParams))

	for k, v := range d.Params {
		buffer.WriteByte(k)
		buffer.Write(v[:])
	}
	return buffer.Bytes()
}

func (d *DoSParams) Unmarshal(r *bytes.Reader) error {
	NParams, err := r.ReadByte()
	if err != nil {
		return err
	}

	d.Params = make(map[byte][8]byte, NParams)

	mem := make([]byte, NParams*8)

	for i := range NParams {
		k, err := r.ReadByte()
		if err != nil {
			return err
		}

		if _, err := r.Read(mem[i*8 : i*8+8]); err != nil {
			return err
		}

		d.Params[k] = [8]byte(mem[i*8 : i*8+8])
	}
	// idk why i tried to optmize this that much
	return nil
}
