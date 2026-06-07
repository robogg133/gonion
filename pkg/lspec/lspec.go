package lspec

import (
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

func Read(r io.Reader) (Lspec, error) {
	header := make([]byte, 2)
	if _, err := r.Read(header); err != nil {
		return Lspec{}, err
	}

	if header[1] > LEN_LSTYPE_ED25519_ID {
		return Lspec{}, fmt.Errorf("lspec: too big %d", header[1])
	}

	specBuffer := make([]byte, header[1])
	if _, err := io.ReadFull(r, specBuffer); err != nil {
		return Lspec{}, err
	}

	spec := lspecType(header[0])
	if spec == nil {
		return Lspec{}, fmt.Errorf("lspec: unknown type %d", header[0])
	}

	if err := spec.Unmarshal(specBuffer); err != nil {
		return Lspec{}, err
	}
	return Lspec{spec: spec}, nil
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
