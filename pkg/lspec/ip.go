package lspec

import (
	"encoding/binary"
	"net/netip"
)

func (i *ip) Marshal() ([]byte, error) {
	b, err := i.ip.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return binary.BigEndian.AppendUint16(b, i.port), nil
}
func (i *ip) UnmarshalBinary(b []byte) error {
	err := i.ip.UnmarshalBinary(b[0 : len(b)-2])

	i.port = binary.BigEndian.Uint16(b[len(b)-2:])
	return err
}

func NewLespecFromIPText(s string) (Lspec, error) {

	i, err := netip.ParseAddrPort(s)
	if err != nil {
		return Lspec{}, err
	}

	var spec Lspec
	if i.Addr().Is4() {
		v4 := &Ipv4{ip: ip{ip: i.Addr(), port: i.Port()}}

		spec.spec = v4
	} else {
		v6 := &Ipv6{ip: ip{ip: i.Addr(), port: i.Port()}}
		spec.spec = v6
	}

	return spec, nil
}
