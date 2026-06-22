package path

import "github.com/robogg133/gonion/pkg/common"

func middleWeightFunc(flags [15]bool, weights common.BandWidthWeight) int64 {
	var weightToUse int64 = int64(weights.Wmm)

	if flags[common.FLAG_GUARD] {
		weightToUse = int64(weights.Wmg)
	} else if flags[common.FLAG_EXIT] {
		weightToUse = int64(weights.Wmm)
	}

	if flags[common.FLAG_GUARD] && flags[common.FLAG_EXIT] {
		weightToUse = int64(weights.Wmd)
	}

	return weightToUse
}

func middleValideFunc(r common.RouterStatus) bool {
	return haveAllKeys(&r)
}
