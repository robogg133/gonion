// Implements relay selection for making circuits
package path

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

type Selector struct {
	consensus *common.Consensus
	list      []common.RouterStatus
	weight    common.BandWidthWeight
	longLive  bool

	guard    *common.RouterStatus
	middles  []*common.RouterStatus
	exit     *common.RouterStatus
	fullPath []*common.RouterStatus
}

type value struct {
	wb  big.Int
	ptr *common.RouterStatus
}

type validateFunc func(r common.RouterStatus) bool
type weightFunc func(flags [15]bool, weights common.BandWidthWeight) int64

// New retains an immutable consensus snapshot. Every selection requires its
// authority authentication and current validity; parsing alone is insufficient.
func New(cns *common.Consensus, longlive bool) *Selector {
	if cns == nil {
		return &Selector{}
	}
	return &Selector{
		consensus: cns,
		list:      cns.RelayInformation,
		weight:    cns.BandWidthWeight,
		longLive:  longlive,
	}
}

// SelectHSRelay selects a general relay with the required introduction or
// rendezvous protocol, never an Exit-policy-dependent final hop.
func (sl *Selector) SelectHSRelay(introduction bool) (*common.RouterStatus, error) {
	return sl.selectRelay(func(r common.RouterStatus) bool {
		if !middleValideFunc(r) || r.StatusFlags[common.FLAG_MIDDLE_ONLY] {
			return false
		}
		if introduction {
			return r.ProtoVersions.HSIntro.CheckIsTrue(common.VERSION_4)
		}
		return r.ProtoVersions.HSRend.CheckIsTrue(common.VERSION_2)
	}, middleWeightFunc, 0)
}

func (sl *Selector) SelectRandomCircuit(hops uint, port uint16) error {
	return sl.selectCircuit(hops, port, nil)
}

// SelectCircuitTo excludes the authenticated final target before selecting the
// guard and middles; appending it to an unrelated path can violate diversity.
func (sl *Selector) SelectCircuitTo(hops uint, target *common.RouterStatus) error {
	if target == nil || !haveAllKeys(target) {
		return fmt.Errorf("invalid final relay")
	}
	// HS link specifiers do not carry family declarations. Use the matching
	// consensus identity's family metadata without replacing its supplied
	// onion key or ordered link-specifier block.
	copyTarget := *target
	for i := range sl.list {
		r := &sl.list[i]
		if r.NodeID != target.NodeID {
			continue
		}
		if !bytes.Equal(r.IdEd25519, target.IdEd25519) {
			return fmt.Errorf("path: final relay identity disagrees with consensus")
		}
		copyTarget.Family, copyTarget.Familys = r.Family, r.Familys
		if copyTarget.Ipv6Addr == "" {
			copyTarget.Ipv6Addr = r.Ipv6Addr
		}
		break
	}
	return sl.selectCircuit(hops, 0, &copyTarget)
}

func (sl *Selector) selectCircuit(hops uint, port uint16, target *common.RouterStatus) error {
	if err := sl.checkConsensus(); err != nil {
		return err
	}
	if hops == 0 || hops > 8 {
		return fmt.Errorf("invalid number of hops: %d need to be greater than 0", hops)
	}

	// Reset previous selection so retries are clean.
	sl.guard = nil
	sl.middles = nil
	sl.exit = nil
	sl.fullPath = nil

	exitInfo := target
	if exitInfo == nil {
		validator, weight := exitValidateFunc, exitWeightFunc
		if port == 0 {
			validator = func(r common.RouterStatus) bool {
				return middleValideFunc(r) && !r.StatusFlags[common.FLAG_MIDDLE_ONLY]
			}
			weight = middleWeightFunc
		}
		var err error
		exitInfo, err = sl.selectRelay(validator, weight, port)
		if err != nil {
			return fmt.Errorf("select final relay: %w", err)
		}
	}
	sl.exit = exitInfo
	hops--

	if hops == 0 {
		sl.fullPath = append(sl.fullPath, exitInfo)
		return nil
	}

	guardInfo, err := sl.selectRelay(guardValideFunc, guardWeightFunc, 0)
	if err != nil {
		return fmt.Errorf("select guard: %w", err)
	}
	sl.guard = guardInfo
	sl.fullPath = append(sl.fullPath, guardInfo)
	hops--

	for range hops {
		middleInfo, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0)
		if err != nil {
			return fmt.Errorf("select middle: %w", err)
		}
		sl.middles = append(sl.middles, middleInfo)
		sl.fullPath = append(sl.fullPath, middleInfo)
	}
	sl.fullPath = append(sl.fullPath, exitInfo)
	return nil
}

func (sl *Selector) Guard() *common.RouterStatus    { return sl.guard }
func (sl *Selector) Exit() *common.RouterStatus     { return sl.exit }
func (sl *Selector) Middle() []*common.RouterStatus { return sl.middles }

func (sl *Selector) Circuit() []*common.RouterStatus { return sl.fullPath }

func (sl *Selector) checkConsensus() error {
	if !sl.consensus.IsAuthenticated() || !sl.consensus.IsLive(time.Now()) {
		return fmt.Errorf("path: an authenticated live consensus is required")
	}
	return nil
}

func (sl *Selector) selectRelay(fn validateFunc, wfn weightFunc, desiredPort uint16) (*common.RouterStatus, error) {
	if err := sl.checkConsensus(); err != nil {
		return nil, err
	}
	var totalBw big.Int
	values := make([]value, 0, len(sl.list))

	for i := range sl.list {
		v := &sl.list[i]

		if desiredPort != 0 && !v.Ports.IsAllowed(desiredPort) {
			continue
		}

		if sl.longLive && !v.StatusFlags[common.FLAG_STABLE] {
			continue
		}
		if !v.StatusFlags[common.FLAG_RUNNING] || !v.StatusFlags[common.FLAG_VALID] {
			continue
		}

		if !fn(*v) || sl.conflicts(v) {
			continue
		}

		w := weightedBandwidth(v.BandWidth, wfn(v.StatusFlags, sl.weight))
		if w <= 0 {
			continue
		}
		dirWeight := int64(sl.consensus.Parameter("bwweightscale", 10000, 1, 1<<31-1))
		if v.StatusFlags[common.FLAG_V2DIR] {
			dirWeight = directoryWeight(v.StatusFlags, sl.weight)
		}
		if dirWeight <= 0 {
			continue
		}
		var entry value
		entry.ptr = v
		entry.wb.SetInt64(w)
		entry.wb.Mul(&entry.wb, big.NewInt(dirWeight))
		totalBw.Add(&totalBw, &entry.wb)
		values = append(values, entry)
	}

	return selectRandom(&totalBw, values)
}

func (sl *Selector) conflicts(r *common.RouterStatus) bool {
	if sl.relaysConflict(sl.guard, r) || sl.relaysConflict(sl.exit, r) {
		return true
	}
	for _, m := range sl.middles {
		if sl.relaysConflict(m, r) {
			return true
		}
	}
	return false
}

func (sl *Selector) relaysConflict(a, b *common.RouterStatus) bool {
	if a == nil || b == nil {
		return false
	}
	if a.NodeID == b.NodeID || (len(a.IdEd25519) == 32 && bytes.Equal(a.IdEd25519, b.IdEd25519)) {
		return true
	}
	// Recompute prefixes from addresses, not the caller-mutable IPLevel cache.
	ip1, err1 := netip.ParseAddr(a.Ipv4Addr)
	ip2, err2 := netip.ParseAddr(b.Ipv4Addr)
	if err1 != nil || err2 != nil || !ip1.Is4() || !ip2.Is4() || netip.PrefixFrom(ip1, 16).Contains(ip2) {
		return true
	}
	if a.Ipv6Addr != "" && b.Ipv6Addr != "" {
		ap1, err1 := netip.ParseAddrPort(a.Ipv6Addr)
		ap2, err2 := netip.ParseAddrPort(b.Ipv6Addr)
		if err1 != nil || err2 != nil || netip.PrefixFrom(ap1.Addr(), 32).Contains(ap2.Addr()) {
			return true
		}
	}
	if sl.consensus.Parameter("use-family-lists", 1, 0, 1) != 0 && declaresFamily(a, b) && declaresFamily(b, a) {
		return true
	}
	return sl.consensus.Parameter("use-family-ids", 1, 0, 1) != 0 && cmpFamily(a.Familys, b.Familys)
}

func declaresFamily(a, b *common.RouterStatus) bool {
	for _, f := range a.Family {
		if bytes.Equal(f.Digest, b.NodeID[:]) || (len(f.Digest) == 0 && f.Nickname != "" && strings.EqualFold(f.Nickname, b.Nickname)) {
			return true
		}
	}
	return false
}

func cmpFamily(b, o []*common.FamilyIDs) bool {
	for _, v := range b {
		if v == nil {
			continue
		}
		for _, r := range o {
			if r == nil || r.Kind != v.Kind {
				continue
			}
			if bytes.Equal(v.Value, r.Value) {
				return true
			}
		}
	}
	return false
}

// C Tor's kb_to_bytes caps consensus bandwidth at INT32_MAX bytes/second.
// Keep the exact numerator: the common scale cancels during selection. This
// preserves tiny positive weights and never promotes an explicit zero.
func weightedBandwidth(bw uint32, positionWeight int64) int64 {
	if positionWeight <= 0 {
		return 0
	}
	return int64(min(uint64(bw)*1000, 1<<31-1)) * positionWeight
}

func directoryWeight(flags [15]bool, weights common.BandWidthWeight) int64 {
	isExit := flags[common.FLAG_EXIT] && !flags[common.FLAG_BAD_EXIT]
	switch {
	case flags[common.FLAG_GUARD] && isExit:
		return int64(weights.Wdb)
	case flags[common.FLAG_GUARD]:
		return int64(weights.Wgb)
	case isExit:
		return int64(weights.Web)
	default:
		return int64(weights.Wmb)
	}
}

func selectRandom(totalBw *big.Int, values []value) (*common.RouterStatus, error) {
	if len(values) == 0 || totalBw.Sign() <= 0 {
		return nil, fmt.Errorf("no eligible relays for weighted pick")
	}
	// Products and the total can exceed 64 bits at legal bwweightscale values.
	n, err := rand.Int(rand.Reader, totalBw)
	if err != nil {
		return nil, err
	}
	for i := range values {
		if n.Cmp(&values[i].wb) < 0 {
			return values[i].ptr, nil
		}
		n.Sub(n, &values[i].wb)
	}
	return nil, fmt.Errorf("path: inconsistent bandwidth total")
}

func haveAllKeys(r *common.RouterStatus) bool {
	if r.NTorOnionKey == nil || r.NTorOnionKey.Curve() != ecdh.X25519() {
		return false
	}
	if r.NodeID == [20]byte{} {
		return false
	}
	if len(r.IdEd25519) != 32 || bytes.Equal(r.IdEd25519, make([]byte, 32)) {
		return false
	}
	ip, err := netip.ParseAddr(r.Ipv4Addr)
	if err != nil || !ip.Is4() || r.ORPort == 0 {
		return false
	}
	if r.Ipv6Addr != "" {
		ap, err := netip.ParseAddrPort(r.Ipv6Addr)
		if err != nil || !ap.Addr().Is6() || ap.Port() == 0 {
			return false
		}
	}
	return true
}
