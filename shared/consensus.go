package shared

import (
	"time"
)

const AUTH_DIR_NUM_AGREEMENTS uint8 = 9

var GlobalConsensus Consensus
var alrInit bool

func SetGlobalConsensus(c Consensus) {
	GlobalConsensus = c
	alrInit = true
}

func GetGlobalConsensus() *Consensus {
	if !alrInit {
		return nil
	}
	return &GlobalConsensus
}

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
	NetowrkStatusVersion uint8

	ValidAfter time.Time
	FreshUntil time.Time
	ValidUntil time.Time

	SharedCurrentValue [32]byte

	routerStatusTmp *RouterStatus

	RelayInformation []RouterStatus

	BandWidthWeight BandWidthWeight
}

type RouterStatus struct {
	Nickname string
	NodeID   [20]byte
	Digest   [20]byte

	Ipv4Addr string
	ORPort   uint16
	IPLevel  uint32

	MicrodescriptorDigest string

	DirPort uint16

	BandWidth uint32

	Ipv6Addr string // like [0000:00a:000:0000::000a]:8443 or empty string

	ProtoVersions Proto
	StatusFlags   [FLAG_ARRAY_LENGTH]bool

	Ports Ports

	OnionKey     []byte
	NtorOnionKey []byte
	IdEd25519    []byte
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
	VERSION_1 uint8 = iota
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

func flagStringToNumber(s string) uint8 {
	//  Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
	switch s {
	case "Authority":
		return FLAG_AUTHORITY
	case "BadExit":
		return FLAG_BAD_EXIT
	case "Exit":
		return FLAG_EXIT
	case "Fast":
		return FLAG_FAST
	case "Guard":
		return FLAG_GUARD
	case "HSDir":
		return FLAG_HIDDEN_SERVICE_DIR
	case "MiddleOnly":
		return FLAG_MIDDLE_ONLY
	case "NoEdConsensus":
		return FLAG_NO_ED_CONSENSUS
	case "Running":
		return FLAG_RUNNING
	case "Stable":
		return FLAG_STABLE
	case "StaleDesc":
		return FLAG_STALE_DESC
	case "Sybil":
		return FLAG_SYBIL
	case "V2Dir":
		return FLAG_V2DIR
	case "Valid":
		return FLAG_VALID
	default:
		return 15
	}
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
