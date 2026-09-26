// Package json parses and formats a consensus as pretty-printed JSON.
package json

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/parsers"
)

// Parser implements common.ConsensusParser using JSON as the document format.
type Parser struct{}

func (Parser) Parse(r io.Reader) (*common.Consensus, error) {
	data, err := parsers.ReadAll(r, 256<<20)
	if err != nil {
		return nil, err
	}
	d := &dtoConsensus{}
	if err := json.Unmarshal(data, d); err != nil {
		return nil, err
	}
	return d.toConsensus()
}

func (Parser) Format(c *common.Consensus) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(dtoFromConsensus(c))
	if err != nil {
		return nil, err
	}
	return b, nil
}

type dtoConsensus struct {
	NetowrkStatusVersion   uint8
	Flavor                 string
	RawDocument            []byte
	AuthorityCertificates  []byte
	Microdescriptors       map[string][]byte
	SharedPreviousValue    string
	HasSharedPreviousValue bool
	HasSharedCurrentValue  bool
	HsdirInterval          *uint64
	Params                 map[string]int32
	ValidAfter             time.Time
	FreshUntil             time.Time
	ValidUntil             time.Time
	SharedCurrentValue     string
	RelayInformation       []dtoRouterStatus
	BandWidthWeight        common.BandWidthWeight
}

type dtoRouterStatus struct {
	Nickname              string
	NodeID                string
	Ipv4Addr              string
	ORPort                uint16
	IPLevel               uint32
	DescriptorDigest      string
	MicrodescriptorDigest string
	MicrodescriptorLoaded bool
	DirPort               uint16
	BandWidth             uint32
	Ipv6Addr              string
	ProtoVersions         common.Proto
	StatusFlags           [common.FLAG_ARRAY_LENGTH + 1]bool
	Ports                 string
	OnionKey              string
	NTorOnionKey          string
	IdEd25519             string
	Family                []common.Family
	Familys               []*common.FamilyIDs
}

func dtoFromConsensus(c *common.Consensus) *dtoConsensus {
	d := &dtoConsensus{
		NetowrkStatusVersion:   c.NetowrkStatusVersion,
		Flavor:                 c.Flavor,
		RawDocument:            bytes.Clone(c.RawDocument),
		AuthorityCertificates:  bytes.Clone(c.AuthorityCertificates),
		Microdescriptors:       c.Microdescriptors,
		SharedPreviousValue:    base64.StdEncoding.EncodeToString(c.SharedPreviousValue[:]),
		HasSharedPreviousValue: c.HasSharedPreviousValue,
		HasSharedCurrentValue:  c.HasSharedCurrentValue,
		HsdirInterval:          c.HsdirInterval,
		Params:                 c.Params,
		ValidAfter:             c.ValidAfter,
		FreshUntil:             c.FreshUntil,
		ValidUntil:             c.ValidUntil,
		SharedCurrentValue:     base64.StdEncoding.EncodeToString(c.SharedCurrentValue[:]),
		BandWidthWeight:        c.BandWidthWeight,
		RelayInformation:       make([]dtoRouterStatus, len(c.RelayInformation)),
	}
	for i := range c.RelayInformation {
		rs := &c.RelayInformation[i]
		d.RelayInformation[i] = dtoRouterStatus{
			Nickname:              rs.Nickname,
			NodeID:                base64.RawStdEncoding.EncodeToString(rs.NodeID[:]),
			Ipv4Addr:              rs.Ipv4Addr,
			ORPort:                rs.ORPort,
			IPLevel:               rs.IPLevel,
			DescriptorDigest:      rs.DescriptorDigest,
			MicrodescriptorDigest: rs.MicrodescriptorDigest,
			MicrodescriptorLoaded: rs.MicrodescriptorLoaded,
			DirPort:               rs.DirPort,
			BandWidth:             rs.BandWidth,
			Ipv6Addr:              rs.Ipv6Addr,
			ProtoVersions:         rs.ProtoVersions,
			StatusFlags:           rs.StatusFlags,
			Ports:                 base64.StdEncoding.EncodeToString(rs.Ports[:]),
			OnionKey:              base64.StdEncoding.EncodeToString(rs.OnionKey),
			IdEd25519:             base64.StdEncoding.EncodeToString(rs.IdEd25519),
			Family:                rs.Family,
			Familys:               rs.Familys,
		}
		if rs.NTorOnionKey != nil {
			d.RelayInformation[i].NTorOnionKey = base64.RawStdEncoding.EncodeToString(rs.NTorOnionKey.Bytes())
		}
	}
	return d
}

func (d *dtoConsensus) toConsensus() (*common.Consensus, error) {
	if len(d.RelayInformation) > common.MaxConsensusRelays {
		return nil, fmt.Errorf("json: too many relays")
	}
	c := &common.Consensus{
		NetowrkStatusVersion:   d.NetowrkStatusVersion,
		Flavor:                 d.Flavor,
		RawDocument:            bytes.Clone(d.RawDocument),
		AuthorityCertificates:  bytes.Clone(d.AuthorityCertificates),
		Microdescriptors:       d.Microdescriptors,
		HasSharedPreviousValue: d.HasSharedPreviousValue,
		HasSharedCurrentValue:  d.HasSharedCurrentValue,
		HsdirInterval:          d.HsdirInterval,
		Params:                 d.Params,
		ValidAfter:             d.ValidAfter,
		FreshUntil:             d.FreshUntil,
		ValidUntil:             d.ValidUntil,
		BandWidthWeight:        d.BandWidthWeight,
		RelayInformation:       make([]common.RouterStatus, len(d.RelayInformation)),
	}
	if d.SharedPreviousValue != "" {
		b, err := base64.StdEncoding.Strict().DecodeString(d.SharedPreviousValue)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("json: invalid shared-rand-previous-value")
		}
		copy(c.SharedPreviousValue[:], b)
	}
	if d.SharedCurrentValue != "" {
		b, err := base64.StdEncoding.DecodeString(d.SharedCurrentValue)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("json: invalid shared-rand-current-value")
		}
		c.SharedCurrentValue = [32]byte(b)
	}
	for i := range d.RelayInformation {
		ds := &d.RelayInformation[i]
		rs := &c.RelayInformation[i]
		rs.Nickname = ds.Nickname
		rs.Ipv4Addr = ds.Ipv4Addr
		rs.ORPort = ds.ORPort
		rs.IPLevel = ds.IPLevel
		rs.DescriptorDigest = ds.DescriptorDigest
		rs.MicrodescriptorDigest = ds.MicrodescriptorDigest
		rs.MicrodescriptorLoaded = ds.MicrodescriptorLoaded
		rs.DirPort = ds.DirPort
		rs.BandWidth = ds.BandWidth
		rs.Ipv6Addr = ds.Ipv6Addr
		rs.ProtoVersions = ds.ProtoVersions
		rs.StatusFlags = ds.StatusFlags
		rs.Family = ds.Family
		rs.Familys = ds.Familys

		var err error
		if ds.NodeID != "" {
			var b []byte
			b, err = base64.RawStdEncoding.Strict().DecodeString(ds.NodeID)
			if err == nil && len(b) != 20 {
				err = fmt.Errorf("invalid relay identity length")
			}
			if err == nil {
				rs.NodeID = [20]byte(b)
			}
		}
		if err == nil && ds.Ports != "" {
			var b []byte
			b, err = base64.StdEncoding.Strict().DecodeString(ds.Ports)
			if err == nil && len(b) != len(rs.Ports) {
				err = fmt.Errorf("invalid ports bitmap length")
			}
			if err == nil {
				copy(rs.Ports[:], b)
			}
		}
		if err == nil && ds.OnionKey != "" {
			rs.OnionKey, err = base64.StdEncoding.DecodeString(ds.OnionKey)
		}
		if err == nil && ds.NTorOnionKey != "" {
			var b []byte
			b, err = base64.RawStdEncoding.DecodeString(ds.NTorOnionKey)
			if err == nil {
				rs.NTorOnionKey, err = ecdh.X25519().NewPublicKey(b)
			}
		}
		if err == nil && ds.IdEd25519 != "" {
			rs.IdEd25519, err = base64.StdEncoding.DecodeString(ds.IdEd25519)
		}
		if err != nil {
			return nil, fmt.Errorf("json: router %d (%s): %w", i, ds.Nickname, err)
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
