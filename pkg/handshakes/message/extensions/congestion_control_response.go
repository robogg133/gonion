package extensions

import "bytes"

const CC_FIELD_RESPONSE byte = 2

type CongestionControlResponse struct {
	SendMeInc uint8
}

func (cc *CongestionControlResponse) Marshal() []byte { return []byte{cc.SendMeInc} }

func (cc *CongestionControlResponse) Unmarshal(r *bytes.Reader) error {
	n, err := r.ReadByte()
	cc.SendMeInc = n
	return err
}
