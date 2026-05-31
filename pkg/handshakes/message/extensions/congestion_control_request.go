package extensions

import "bytes"

const CC_FIELD_REQUEST byte = 1

type CongestionControlRequest struct{}

func (*CongestionControlRequest) ID() uint8                       { return CC_FIELD_REQUEST }
func (*CongestionControlRequest) Marshal() []byte                 { return nil }
func (*CongestionControlRequest) Unmarshal(r *bytes.Reader) error { return nil }
