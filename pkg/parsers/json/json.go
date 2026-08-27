// Package json parses and formats a consensus as pretty-printed JSON.
package json

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

// Parser implements common.ConsensusParser using JSON as the document format.
type Parser struct{}

func (Parser) Parse(r io.Reader) (*common.Consensus, error) {
	d := &dtoConsensus{}
	if err := json.NewDecoder(r).Decode(d); err != nil {
		return nil, err
	}
	return d.toConsensus()
}

func (Parser) Format(c *common.Consensus) ([]byte, error) {
	b, err := json.MarshalIndent(dtoFromConsensus(c), "", "  ")
	if err != nil {
		return nil, err
	}
	return b, nil
}

type dtoConsensus struct {
	NetowrkStatusVersion uint8
	ValidAfter           time.Time
	FreshUntil           time.Time
	ValidUntil           time.Time
	SharedCurrentValue   string
	RelayInformation     []dtoRouterStatus
	BandWidthWeight      common.BandWidthWeight
}

type dtoRouterStatus struct {
	Nickname              string
	NodeID                string
	Ipv4Addr              string
	ORPort                uint16
	IPLevel               uint32
	MicrodescriptorDigest string
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
		NetowrkStatusVersion: c.NetowrkStatusVersion,
		ValidAfter:           c.ValidAfter,
		FreshUntil:           c.FreshUntil,
		ValidUntil:           c.ValidUntil,
		SharedCurrentValue:   base64.StdEncoding.EncodeToString(c.SharedCurrentValue[:]),
		BandWidthWeight:      c.BandWidthWeight,
		RelayInformation:     make([]dtoRouterStatus, len(c.RelayInformation)),
	}
	for i := range c.RelayInformation {
		rs := &c.RelayInformation[i]
		d.RelayInformation[i] = dtoRouterStatus{
			Nickname:              rs.Nickname,
			NodeID:                base64.RawStdEncoding.EncodeToString(rs.NodeID[:]),
			Ipv4Addr:              rs.Ipv4Addr,
			ORPort:                rs.ORPort,
			IPLevel:               rs.IPLevel,
			MicrodescriptorDigest: rs.MicrodescriptorDigest,
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
	c := &common.Consensus{
		NetowrkStatusVersion: d.NetowrkStatusVersion,
		ValidAfter:           d.ValidAfter,
		FreshUntil:           d.FreshUntil,
		ValidUntil:           d.ValidUntil,
		BandWidthWeight:      d.BandWidthWeight,
		RelayInformation:     make([]common.RouterStatus, len(d.RelayInformation)),
	}
	if d.SharedCurrentValue != "" {
		b, err := base64.StdEncoding.DecodeString(d.SharedCurrentValue)
		if err != nil {
			return nil, fmt.Errorf("json: shared-rand-current-value: %w", err)
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
		rs.MicrodescriptorDigest = ds.MicrodescriptorDigest
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
			b, err = base64.RawStdEncoding.DecodeString(ds.NodeID)
			if err == nil {
				rs.NodeID = [20]byte(b)
			}
		}
		if err == nil && ds.Ports != "" {
			var b []byte
			b, err = base64.StdEncoding.DecodeString(ds.Ports)
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
	return c, nil
}