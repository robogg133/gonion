package common

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const AUTH_DIR_NUM_AGREEMENTS uint8 = 9

// GlobalConsensus is retained for source compatibility only.
// Deprecated: use GetGlobalConsensus and SetGlobalConsensus. Direct access is
// not synchronized and must not be used concurrently with publication.
var GlobalConsensus *Consensus

var consensusMu sync.RWMutex
var globalSnapshot *Consensus

// SetGlobalConsensus takes an owned copy; callers may keep their old snapshot.
// This function does not authenticate directory signatures.
func SetGlobalConsensus(c *Consensus) {
	snapshot := c.Clone()
	legacy := c.Clone()
	consensusMu.Lock()
	defer consensusMu.Unlock()
	globalSnapshot = snapshot
	GlobalConsensus = legacy
}

// GetGlobalConsensus returns an independent snapshot, safe for caller mutation.
func GetGlobalConsensus() *Consensus {
	consensusMu.RLock()
	defer consensusMu.RUnlock()
	return globalSnapshot.Clone()
}

const (
	ConsensusFlavorNS        = "ns"
	ConsensusFlavorMicrodesc = "microdesc"
	// Local resource limits, not Tor protocol constants.
	MaxConsensusSize   = 16 << 20
	MaxConsensusRelays = 20000
)

const (
	FLAG_AUTHORITY uint8 = iota
	FLAG_BAD_EXIT
	FLAG_EXIT
	FLAG_FAST
	FLAG_GUARD
	FLAG_HIDDEN_SERVICE_DIR
	FLAG_MIDDLE_ONLY
	FLAG_NO_ED_CONSENSUS
	FLAG_STABLE
	FLAG_STALE_DESC
	FLAG_RUNNING
	FLAG_VALID
	FLAG_V2DIR
	FLAG_SYBIL
	FLAG_ARRAY_LENGTH
)

type Ports [65536 / 8]byte

func (p *Ports) SetPort(n uint16, on bool) {
	if on {
		p[n/8] |= 1 << (n % 8)
	} else {
		p[n/8] &^= 1 << (n % 8)
	}
}
func (p *Ports) IsAllowed(n uint16) bool {
	return p[n/8]&(1<<(n%8)) != 0
}

func (p *Ports) turnOnAllPorts() {
	for i := range p {
		p[i] = 0xFF
	}
}

type Consensus struct {
	// Not serialized: persisted models must be reauthenticated from RawDocument.
	trusted              *Consensus // Private, owned verification result; never exposes mutable fields.
	hydrated             bool       // Set only on a fully verified private snapshot.
	NetowrkStatusVersion uint8
	Flavor               string
	// RawDocument preserves the signed bytes, including signatures. Parsing and
	// hydration do NOT imply signature verification or an authority quorum.
	RawDocument           []byte
	AuthorityCertificates []byte
	Microdescriptors      map[string][]byte // Original bytes keyed by their SHA-256 digest.

	ValidAfter time.Time
	FreshUntil time.Time
	ValidUntil time.Time

	SharedCurrentValue     [32]byte
	SharedPreviousValue    [32]byte
	HasSharedCurrentValue  bool
	HasSharedPreviousValue bool

	HsdirInterval *uint64
	Params        map[string]int32

	RelayInformation []RouterStatus

	BandWidthWeight BandWidthWeight
}

type RouterStatus struct {
	// LinkSpecifiers is set only for authenticated HS extension targets. It is
	// the exact NSPEC-prefixed block, not a field from the relay consensus.
	LinkSpecifiers []byte
	Nickname       string
	NodeID         [20]byte

	Ipv4Addr string
	ORPort   uint16
	IPLevel  uint32

	DescriptorDigest      string // SHA-1 server descriptor digest, ns flavor only.
	MicrodescriptorDigest string
	MicrodescriptorLoaded bool // All supported microdescriptor fields were applied.

	DirPort uint16

	BandWidth uint32

	Ipv6Addr string // like [0000:00a:000:0000::000a]:8443 or empty string

	ProtoVersions Proto
	StatusFlags   [FLAG_ARRAY_LENGTH + 1]bool

	Ports Ports

	OnionKey     []byte
	NTorOnionKey *ecdh.PublicKey
	IdEd25519    []byte

	Family  []Family
	Familys []*FamilyIDs
}

// Clone copies every mutable field. ecdh.PublicKey is immutable.
func (c *Consensus) Clone() *Consensus {
	if c == nil {
		return nil
	}
	out := *c
	out.RawDocument = bytes.Clone(c.RawDocument)
	out.AuthorityCertificates = bytes.Clone(c.AuthorityCertificates)
	if c.Microdescriptors != nil {
		out.Microdescriptors = make(map[string][]byte, len(c.Microdescriptors))
		for digest, raw := range c.Microdescriptors {
			out.Microdescriptors[digest] = bytes.Clone(raw)
		}
	}
	if c.Params != nil {
		out.Params = make(map[string]int32, len(c.Params))
		for key, value := range c.Params {
			out.Params[key] = value
		}
	}
	if c.HsdirInterval != nil {
		n := *c.HsdirInterval
		out.HsdirInterval = &n
	}
	out.RelayInformation = slices.Clone(c.RelayInformation)
	for i := range out.RelayInformation {
		out.RelayInformation[i] = *CloneRouter(&c.RelayInformation[i])
	}
	return &out
}

// CloneRouter separates selected relay views, including nested family and key bytes.
func CloneRouter(src *RouterStatus) *RouterStatus {
	if src == nil {
		return nil
	}
	r := *src
	r.OnionKey = bytes.Clone(r.OnionKey)
	r.LinkSpecifiers = bytes.Clone(r.LinkSpecifiers)
	r.IdEd25519 = bytes.Clone(r.IdEd25519)
	r.Family = slices.Clone(r.Family)
	for j := range r.Family {
		r.Family[j].Digest = bytes.Clone(r.Family[j].Digest)
	}
	r.Familys = slices.Clone(r.Familys)
	for j, f := range r.Familys {
		if f != nil {
			v := *f
			v.Value = bytes.Clone(f.Value)
			r.Familys[j] = &v
		}
	}
	return &r
}

// Validate checks the supported consensus model, not its cryptographic trust.
func (c *Consensus) Validate() error {
	if c == nil || c.NetowrkStatusVersion != 3 {
		return fmt.Errorf("consensus: expected network-status version 3")
	}
	if c.Flavor != ConsensusFlavorNS && c.Flavor != ConsensusFlavorMicrodesc {
		return fmt.Errorf("consensus: unsupported flavor %q", c.Flavor)
	}
	if c.ValidAfter.IsZero() || !c.FreshUntil.After(c.ValidAfter) || !c.ValidUntil.After(c.FreshUntil) {
		return fmt.Errorf("consensus: invalid validity interval")
	}
	if len(c.RawDocument) > MaxConsensusSize || len(c.AuthorityCertificates) > 4<<20 || len(c.Microdescriptors) > MaxConsensusRelays || len(c.RelayInformation) > MaxConsensusRelays {
		return fmt.Errorf("consensus: resource limit exceeded")
	}
	seen := make(map[[20]byte]bool, len(c.RelayInformation))
	for i := range c.RelayInformation {
		r := &c.RelayInformation[i]
		if seen[r.NodeID] {
			return fmt.Errorf("consensus: duplicate relay identity")
		}
		seen[r.NodeID] = true
		ip, err := netip.ParseAddr(r.Ipv4Addr)
		if err != nil || !ip.Is4() || r.ORPort == 0 {
			return fmt.Errorf("consensus: relay %d has invalid OR address", i)
		}
		if r.Ipv6Addr != "" {
			a, err := netip.ParseAddrPort(r.Ipv6Addr)
			if err != nil || !a.Addr().Is6() || a.Port() == 0 {
				return fmt.Errorf("consensus: relay %d has invalid IPv6 OR address", i)
			}
		}
		digest, size := r.DescriptorDigest, 20
		if c.Flavor == ConsensusFlavorMicrodesc {
			digest, size = r.MicrodescriptorDigest, 32
			if r.DescriptorDigest != "" {
				return fmt.Errorf("consensus: server digest in microdesc flavor")
			}
		} else if r.MicrodescriptorDigest != "" || r.MicrodescriptorLoaded {
			return fmt.Errorf("consensus: microdescriptor in ns flavor")
		}
		b, err := base64.RawStdEncoding.Strict().DecodeString(digest)
		if err != nil || len(b) != size {
			return fmt.Errorf("consensus: relay %d has invalid descriptor digest", i)
		}
		if len(r.IdEd25519) != 0 && len(r.IdEd25519) != 32 {
			return fmt.Errorf("consensus: relay %d has invalid Ed25519 key length", i)
		}
		if r.MicrodescriptorLoaded && (r.NTorOnionKey == nil || r.NTorOnionKey.Curve() != ecdh.X25519()) {
			return fmt.Errorf("consensus: relay %d missing X25519 key", i)
		}
	}
	return nil
}

// Parameter applies the protocol bounds and default to a signed consensus param.
func (c *Consensus) Parameter(name string, fallback, lower, upper int32) int {
	if c == nil {
		return int(fallback)
	}
	value, ok := c.Params[name]
	if !ok {
		return int(fallback)
	}
	return int(min(upper, max(lower, value)))
}

// IsAuthenticated reports an association with privately owned authenticated
// state, not that the mutable exported fields of this view are authenticated.
func (c *Consensus) IsAuthenticated() bool {
	return c != nil && c.trusted != nil
}

// Trusted returns a fresh view of the privately owned authenticated state.
// Exported fields on c (including signed bytes) are never used as trust evidence.
func (c *Consensus) Trusted() *Consensus {
	if c == nil || c.trusted == nil {
		return nil
	}
	view := c.trusted.Clone()
	view.trusted = c.trusted
	return view
}

// OwnAuthenticatedHydration derives relay keys and policies from digest-bound
// original microdescriptor bytes, never from caller-supplied model fields.
func (c *Consensus) OwnAuthenticatedHydration(descriptors map[string][]byte) (*Consensus, error) {
	if c == nil || c.trusted == nil {
		return nil, fmt.Errorf("consensus: authenticated source required")
	}
	base := c.trusted
	if base.Flavor != ConsensusFlavorMicrodesc || len(base.RelayInformation) == 0 || len(descriptors) > MaxConsensusRelays {
		return nil, fmt.Errorf("consensus: incomplete hydration")
	}
	owned := base.Clone()
	owned.trusted = nil
	owned.Microdescriptors = make(map[string][]byte, len(descriptors))
	for i, r := range base.RelayInformation {
		raw := descriptors[r.MicrodescriptorDigest]
		md, err := ParseMicrodescriptor(raw, r.MicrodescriptorDigest)
		if err != nil {
			return nil, err
		}
		owned.Microdescriptors[r.MicrodescriptorDigest] = bytes.Clone(raw)
		if r.StatusFlags[FLAG_NO_ED_CONSENSUS] {
			md.IdEd25519 = nil
		}
		key, err := ecdh.X25519().NewPublicKey(md.NTorOnionKey)
		if err != nil {
			return nil, fmt.Errorf("consensus: invalid microdescriptor ntor key: %w", err)
		}
		owned.RelayInformation[i].OnionKey = md.OnionKey
		owned.RelayInformation[i].NTorOnionKey = key
		owned.RelayInformation[i].IdEd25519 = md.IdEd25519
		owned.RelayInformation[i].Family = md.Family
		owned.RelayInformation[i].Familys = md.Familys
		owned.RelayInformation[i].Ports = *md.ExitRules
		owned.RelayInformation[i].MicrodescriptorLoaded = true
	}
	owned.hydrated = true
	view := owned.Clone()
	view.trusted = owned
	return view, nil
}

// IsLive deliberately does not allow future or expired documents at bootstrap.
func (c *Consensus) IsLive(now time.Time) bool {
	if c == nil {
		return false
	}
	if c.trusted != nil {
		c = c.trusted
	}
	return !now.Before(c.ValidAfter) && now.Before(c.ValidUntil)
}

// TrustedHydrated checks only the privately owned, verified descriptor state.
func (c *Consensus) TrustedHydrated() bool {
	return c != nil && c.trusted != nil && c.trusted.hydrated
}

// IsHydrated describes this model's fields, not their authenticity.
func (c *Consensus) IsHydrated() bool {
	if c == nil {
		return false
	}
	if c.Flavor != ConsensusFlavorMicrodesc || len(c.RelayInformation) == 0 {
		return false
	}
	for i := range c.RelayInformation {
		r := &c.RelayInformation[i]
		if !r.MicrodescriptorLoaded || r.NTorOnionKey == nil {
			return false
		}
	}
	return true
}

type BandWidthWeight struct {
	Wbd int32
	Wbe int32
	Wbg int32
	Wbm int32
	Wdb int32
	Web int32
	Wed int32
	Wee int32
	Weg int32
	Wem int32
	Wgb int32
	Wgd int32
	Wgg int32
	Wgm int32
	Wmb int32
	Wmd int32
	Wme int32
	Wmg int32
	Wmm int32
}

const (
	VERSION_1 uint8 = iota + 1
	VERSION_2
	VERSION_3
	VERSION_4
	VERSION_5
	VERSION_6
)

type VersionValue byte

type Proto struct {
	Link      VersionValue
	LinkAuth  VersionValue
	Relay     VersionValue
	DirCache  VersionValue
	HSDir     VersionValue
	HSIntro   VersionValue
	HSRend    VersionValue
	Desc      VersionValue
	Microdesc VersionValue
	Cons      VersionValue
	Padding   VersionValue
	FlowCtrl  VersionValue
	Conflux   VersionValue
}

func (v *VersionValue) CheckIsTrue(n uint8) bool {
	b := byte(*v)

	if b&(1<<n) != 0 {
		return true
	}

	return false
}

func (s *VersionValue) SetValue(n uint8, value bool) {
	if value {
		*s |= 1 << n
	} else {
		*s &^= 1 << n
	}
}
