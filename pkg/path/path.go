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
	if hops <= 0 {
		return fmt.Errorf("invalid number of hops: %d need to be greater than 0", hops)
	}

	exitInfo, err := sl.selectRelay(exitValidateFunc, exitWeightFunc, port)
	if err != nil {
		return err
	}
	sl.exit = exitInfo
	hops--

	if hops <= 0 {
		sl.fullPath = append(sl.fullPath, exitInfo)
		return nil
	}

	guardInfo, err := sl.selectRelay(guardValideFunc, guardWeightFunc, 0)
	if err != nil {
		return err
	}
	sl.guard = guardInfo
	sl.fullPath = append(sl.fullPath, guardInfo)
	hops--

	for range hops {
		middleInfo, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0)
		if err != nil {
			return err
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

	for _, v := range sl.list {

		if desiredPort != 0 {
			if !v.Ports.IsAllowed(desiredPort) {
				continue
			}
		}

		if sl.longLive && !v.StatusFlags[common.FLAG_STABLE] {
			continue
		}
		if !v.StatusFlags[common.FLAG_RUNNING] && !v.StatusFlags[common.FLAG_VALID] {
			continue
		}

		if !fn(v) {
			continue
		}

		w := int64(v.BandWidth) * wfn(v.StatusFlags, sl.weight) / 10000
		totalBw += w
		values = append(values, value{wb: w, ptr: &v})
	}

	// TODO: old family checks
	for {
		random, err := selectRandom(totalBw, values)
		if err != nil {
			return nil, err
		}

		if sl.guard != nil {
			if sl.guard.IPLevel == random.IPLevel || cmpFamily(sl.guard.Familys, random.Familys) {
				continue
			}
		}
		if sl.exit != nil {
			if sl.exit.IPLevel == random.IPLevel || cmpFamily(sl.exit.Familys, random.Familys) {
				continue
			}
		}

		if sl.middles != nil {
			valid := true
			for _, m := range sl.middles {
				if m.IPLevel == random.IPLevel {
					valid = false
					break
				}

				if cmpFamily(m.Familys, random.Familys) {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
		}
		return random, nil
	}

}

func cmpFamily(b, o []*common.FamilyIDs) (matched bool) {
	for _, v := range b {
		if v == nil {
			continue
		}
		for _, r := range o {
			if r == nil {
				continue
			}
			if r.Kind != v.Kind {
				continue
			}
			if bytes.Equal(v.Value, r.Value) {
				return true
			}
		}
	}
	return false
}

func selectRandom(totalBw int64, values []value) (*common.RouterStatus, error) {

	sum := int64(0)
	for {
		randonN := rand.Int64N(totalBw)

		for _, v := range values {
			sum += v.wb
			if sum >= randonN {
				return v.ptr, nil
			}
		}
	}
}
