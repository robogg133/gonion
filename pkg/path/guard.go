package path

import "github.com/robogg133/gonion/pkg/common"

func guardWeightFunc(flags [15]bool, weights common.BandWidthWeight) int64 {
	var weightToUse int64 = int64(weights.Wgg)
	if flags[common.FLAG_EXIT] {
		weightToUse = int64(weights.Wgd)
	}
	return weightToUse
}

func guardValideFunc(r common.RouterStatus) bool {
	if !haveAllKeys(&r) {
		return false
	}

	return r.StatusFlags[common.FLAG_GUARD] && r.StatusFlags[common.FLAG_FAST] && r.StatusFlags[common.FLAG_STABLE] && r.StatusFlags[common.FLAG_V2DIR]
}
