package lspec

import (
	"fmt"
	"io"
	"net/netip"
)

const (
	LSTYPE_IPV4 uint8 = iota
	LSTYPE_IPV6
	LSTYPE_LEGACY_ID
	LSTYPE_ED25519_ID
)

const (
	LEN_LSTYPE_IPV4       uint8 = 6
	LEN_LSTYPE_IPV6       uint8 = 18
	LEN_LSTYPE_LEGACY_ID  uint8 = 20
	LEN_LSTYPE_ED25519_ID uint8 = 32
)

type Lspec struct {
	spec interface {
		Type() uint8
		Len() uint8
		Marshal() ([]byte, error)
		Unmarshal(b []byte) error
	}
}

type ip struct {
	ip netip.AddrPort
}
type (
	Ipv4 ip
	Ipv6 ip
)
type (
	LegacyID  [20]byte
	Ed25519ID [32]byte
)

func (lspec *Lspec) Write(w io.Writer) error {

	if _, err := w.Write([]byte{lspec.spec.Type(), lspec.spec.Len()}); err != nil {
		return err
	}

	b, err := lspec.spec.Marshal()
	if err != nil {
		return err
	}

	_, err = w.Write(b)
	return err
}

func (LegacyID) Type() uint8                 { return LSTYPE_LEGACY_ID }
func (LegacyID) Len() uint8                  { return LEN_LSTYPE_LEGACY_ID }
func (id LegacyID) Marshal() ([]byte, error) { return id[:], nil }
func (id *LegacyID) Unmarshal(b []byte) error {
	if len(b) > int(LEN_LSTYPE_LEGACY_ID) {
		return fmt.Errorf("lspec: too big expecting len %d", LEN_LSTYPE_LEGACY_ID)
	}
	*id = [20]byte(b)
	return nil
}

func (Ed25519ID) Type() uint8                 { return LSTYPE_ED25519_ID }
func (Ed25519ID) Len() uint8                  { return LEN_LSTYPE_ED25519_ID }
func (id Ed25519ID) Marshal() ([]byte, error) { return id[:], nil }
func (id *Ed25519ID) Unmarshal(b []byte) error {
	if len(b) > int(LEN_LSTYPE_LEGACY_ID) {
		return fmt.Errorf("lspec: too big expecting len %d", LEN_LSTYPE_LEGACY_ID)
	}
	*id = [32]byte(b)
	return nil
}

func (Ipv4) Type() uint8 { return LSTYPE_IPV4 }
func (Ipv4) Len() uint8  { return LEN_LSTYPE_IPV4 }

func (Ipv6) Type() uint8 { return LSTYPE_IPV6 }
func (Ipv6) Len() uint8  { return LEN_LSTYPE_IPV6 }

func (i *ip) Marshal() ([]byte, error) {
	return i.ip.MarshalBinary()
}
