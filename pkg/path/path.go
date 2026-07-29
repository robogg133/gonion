// Implements relay selection for making circuits
package path

import (
	"bytes"
	"fmt"
	"math/rand/v2"

	"github.com/robogg133/gonion/pkg/common"
)

type Selector struct {
	list     []common.RouterStatus
	weight   common.BandWidthWeight
	longLive bool

	guard    *common.RouterStatus
	middles  []*common.RouterStatus
	exit     *common.RouterStatus
	fullPath []*common.RouterStatus
}

type value struct {
	wb  int64
	ptr *common.RouterStatus
}

type validateFunc func(r common.RouterStatus) bool
type weightFunc func(flags [15]bool, weights common.BandWidthWeight) int64

func New(cns *common.Consensus, longlive bool) *Selector {
	return &Selector{
		list:     cns.RelayInformation,
		weight:   cns.BandWidthWeight,
		longLive: longlive,
	}
}

func (sl *Selector) SelectRandomCircuit(hops uint, port uint16) error {
	if hops == 0 {
		return fmt.Errorf("invalid number of hops: %d need to be greater than 0", hops)
	}

	// Reset previous selection so retries are clean.
	sl.guard = nil
	sl.middles = nil
	sl.exit = nil
	sl.fullPath = nil

	exitInfo, err := sl.selectRelay(exitValidateFunc, exitWeightFunc, port)
	if err != nil {
		return fmt.Errorf("select exit: %w", err)
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

func (sl *Selector) selectRelay(fn validateFunc, wfn weightFunc, desiredPort uint16) (*common.RouterStatus, error) {
	var totalBw int64
	var values []value

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

		if !fn(*v) {
			continue
		}

		w := weightedBandwidth(int64(v.BandWidth), wfn(v.StatusFlags, sl.weight))
		if w <= 0 {
			continue
		}
		totalBw += w
		values = append(values, value{wb: w, ptr: v})
	}

	if len(values) == 0 || totalBw <= 0 {
		return nil, fmt.Errorf("no eligible relays (candidates=%d total_bw=%d port=%d)", len(values), totalBw, desiredPort)
	}

	// Family /16 uniqueness: sample until a free relay is found.
	const maxAttempts = 256
	for range maxAttempts {
		random, err := selectRandom(totalBw, values)
		if err != nil {
			return nil, err
		}
		if sl.conflicts(random) {
			continue
		}
		return random, nil
	}
	return nil, fmt.Errorf("could not pick relay without family/ip conflict after %d attempts", maxAttempts)
}

func (sl *Selector) conflicts(r *common.RouterStatus) bool {
	if sl.guard != nil {
		if sl.guard.IPLevel == r.IPLevel || cmpFamily(sl.guard.Familys, r.Familys) {
			return true
		}
	}
	if sl.exit != nil {
		if sl.exit.IPLevel == r.IPLevel || cmpFamily(sl.exit.Familys, r.Familys) {
			return true
		}
	}
	for _, m := range sl.middles {
		if m.IPLevel == r.IPLevel || cmpFamily(m.Familys, r.Familys) {
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

// weightedBandwidth applies consensus position weights. Falls back to raw
// bandwidth when weights are missing/zero so selection never collapses to 0.
func weightedBandwidth(bw, positionWeight int64) int64 {
	if bw <= 0 {
		return 0
	}
	if positionWeight <= 0 {
		return bw
	}
	w := bw * positionWeight / 10000
	if w <= 0 {
		return 1
	}
	return w
}

func selectRandom(totalBw int64, values []value) (*common.RouterStatus, error) {
	if len(values) == 0 || totalBw <= 0 {
		return nil, fmt.Errorf("no eligible relays for weighted pick")
	}

	// r in [0, totalBw)
	r := rand.Int64N(totalBw)
	var sum int64
	for _, v := range values {
		sum += v.wb
		if r < sum {
			return v.ptr, nil
		}
	}
	// Floating-point / rounding safety: return last candidate.
	return values[len(values)-1].ptr, nil
}

func haveAllKeys(r *common.RouterStatus) bool {
	if r.NTorOnionKey == nil {
		return false
	}
	if r.NodeID == [20]byte{} {
		return false
	}
	if len(r.IdEd25519) == 0 {
		return false
	}
	return true
}
