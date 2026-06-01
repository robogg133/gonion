// Implements relay selection for making circuits
package path

import (
	"errors"
	"math/rand/v2"

	"github.com/robogg133/gonion/pkg/common"
)

type Selector struct {
	list       []common.RouterStatus
	weight     *common.BandWidthWeight
	longLive   bool
	targetExit uint16

	guard   *common.RouterStatus
	middles []*common.RouterStatus
	exit    *common.RouterStatus
}

type value struct {
	wb  int64
	ptr *common.RouterStatus
}

type validateFunc func(r common.RouterStatus) bool
type weightFunc func(flags [15]bool, weights common.BandWidthWeight) int64

func (sl *Selector) selectRelay(fn validateFunc, wfn weightFunc) (*common.RouterStatus, error) {
	var totalBw int64
	var values []value

	for _, v := range sl.list {
		if sl.longLive && !v.StatusFlags[common.FLAG_STABLE] {
			continue
		}
		if !fn(v) {
			continue
		}

		w := int64(v.BandWidth) * wfn(v.StatusFlags, *sl.weight) / 10000
		totalBw += w
		values = append(values, value{wb: w, ptr: &v})
	}

	return selectRandom(totalBw, values)
}

func selectRandom(totalBw int64, values []value) (*common.RouterStatus, error) {

	alrTry := false
retry:
	randonN := rand.Int64N(totalBw)

	for _, v := range values {
		if v.wb >= randonN {
			return v.ptr, nil
		}
	}

	if alrTry {
		return nil, errors.New("selectExit: can not select exit node")
	}

	alrTry = true
	goto retry
}
