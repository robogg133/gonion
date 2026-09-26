package lspec

import (
	"bytes"
	"crypto/ed25519"
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

type spec interface {
	Type() uint8
	Len() uint8
	Marshal() ([]byte, error)
	Unmarshal(b []byte) error
}

type Lspec struct {
	spec spec
}

// Unknown specifiers must survive descriptor-to-EXTEND2 forwarding verbatim.
type opaqueSpec struct {
	kind uint8
	body []byte
}

func (s *opaqueSpec) Type() uint8              { return s.kind }
func (s *opaqueSpec) Len() uint8               { return uint8(len(s.body)) }
func (s *opaqueSpec) Marshal() ([]byte, error) { return bytes.Clone(s.body), nil }
func (s *opaqueSpec) Unmarshal(b []byte) error {
	if len(b) > 255 {
		return fmt.Errorf("lspec: oversized specifier")
	}
	s.body = bytes.Clone(b)
	return nil
}

type ip struct {
	ip   netip.Addr
	port uint16
}
type (
	Ipv4 struct{ ip ip }
	Ipv6 struct{ ip ip }
)
type (
	LegacyID  [20]byte
	Ed25519ID ed25519.PublicKey
)

func (lspec *Lspec) Write(w io.Writer) error {
	if lspec.spec == nil {
		return fmt.Errorf("lspec: missing specifier")
	}
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
func (lspec *Lspec) Type() uint8 {
	return lspec.spec.Type()
}

// Bytes returns the bare specifier body (no TYPE/LEN header).
func (lspec *Lspec) Bytes() ([]byte, error) {
	if lspec.spec == nil {
		return nil, fmt.Errorf("lspec: missing specifier")
	}
	return lspec.spec.Marshal()
}

func Read(r io.Reader) (Lspec, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return Lspec{}, err
	}

	specBuffer := make([]byte, header[1])
	if _, err := io.ReadFull(r, specBuffer); err != nil {
		return Lspec{}, err
	}

	return FromWire(header[0], specBuffer)
}

func (LegacyID) Type() uint8                 { return LSTYPE_LEGACY_ID }
func (LegacyID) Len() uint8                  { return LEN_LSTYPE_LEGACY_ID }
func (id LegacyID) Marshal() ([]byte, error) { return id[:], nil }
func (id *LegacyID) Unmarshal(b []byte) error {
	if len(b) != int(LEN_LSTYPE_LEGACY_ID) {
		return fmt.Errorf("lspec: too big expecting len %d", LEN_LSTYPE_LEGACY_ID)
	}
	*id = [20]byte(b)
	return nil
}

func (Ed25519ID) Type() uint8                 { return LSTYPE_ED25519_ID }
func (Ed25519ID) Len() uint8                  { return LEN_LSTYPE_ED25519_ID }
func (id Ed25519ID) Marshal() ([]byte, error) { return id[:], nil }
func (id *Ed25519ID) Unmarshal(b []byte) error {
	if len(b) != int(LEN_LSTYPE_ED25519_ID) {
		return fmt.Errorf("lspec: too big expecting len %d", LEN_LSTYPE_ED25519_ID)
	}
	*id = b
	return nil
}

func (*Ipv4) Type() uint8                 { return LSTYPE_IPV4 }
func (*Ipv4) Len() uint8                  { return LEN_LSTYPE_IPV4 }
func (v4 *Ipv4) Marshal() ([]byte, error) { return v4.ip.Marshal() }
func (v4 *Ipv4) Unmarshal(b []byte) error { return v4.ip.UnmarshalBinary(b) }

func (*Ipv6) Type() uint8                 { return LSTYPE_IPV6 }
func (*Ipv6) Len() uint8                  { return LEN_LSTYPE_IPV6 }
func (v6 *Ipv6) Marshal() ([]byte, error) { return v6.ip.Marshal() }
func (v6 *Ipv6) Unmarshal(b []byte) error { return v6.ip.UnmarshalBinary(b) }

func NewNodeID(nodeID [20]byte) Lspec {
	id := new(LegacyID)
	*id = nodeID
	return Lspec{spec: id}
}
func NewEd25519ID(ed25519id ed25519.PublicKey) Lspec {
	if len(ed25519id) != 32 {
		panic(fmt.Errorf("ed25519id not 32 bytes length got %d", len(ed25519id)))
	}
	id := new(Ed25519ID)
	*id = Ed25519ID(ed25519id)
	return Lspec{spec: id}
}

func lspecType(lstype uint8) spec {
	switch lstype {
	case LSTYPE_IPV4:
		return &Ipv4{}
	case LSTYPE_IPV6:
		return &Ipv6{}
	case LSTYPE_LEGACY_ID:
		return &LegacyID{}
	case LSTYPE_ED25519_ID:
		return &Ed25519ID{}
	default:
		return nil
	}
}

// FromWire builds an Lspec from a raw (type-less) wire body. It is the inverse
// of spec.Marshal and is used by readers that already consumed the TYPE(1)
// LEN(1) header (e.g. descriptor intro-point link specifier lists).
func FromWire(lsType uint8, body []byte) (Lspec, error) {
	s := lspecType(lsType)
	if s == nil {
		raw := &opaqueSpec{kind: lsType}
		if err := raw.Unmarshal(body); err != nil {
			return Lspec{}, err
		}
		return Lspec{spec: raw}, nil
	}
	if len(body) != int(s.Len()) {
		return Lspec{}, fmt.Errorf("lspec: type %d body len %d want %d", lsType, len(body), s.Len())
	}
	if err := s.Unmarshal(body); err != nil {
		return Lspec{}, err
	}
	return Lspec{spec: s}, nil
}
