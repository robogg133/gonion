package path

import "github.com/robogg133/gonion/pkg/common"

func guardWeightFunc(flags [15]bool, weights common.BandWidthWeight) int64 {
	var weightToUse int64 = int64(weights.Wee)
	if flags[common.FLAG_GUARD] {
		weightToUse = int64(weights.Wed)
	}
	return weightToUse
}
