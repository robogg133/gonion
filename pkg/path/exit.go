package path

import (
	"github.com/robogg133/gonion/pkg/common"
)

func exitWeightFunc(flags [15]bool, weights common.BandWidthWeight) int64 {
	var weightToUse int64 = int64(weights.Wee)
	if flags[common.FLAG_GUARD] {
		weightToUse = int64(weights.Wed)
	}
	return weightToUse
}

func exitValidateFunc(r common.RouterStatus) bool {
	if !haveAllKeys(&r) {
		return false
	}
	if !r.StatusFlags[common.FLAG_EXIT] || r.StatusFlags[common.FLAG_BAD_EXIT] {
		return false
	}
	return true
}
