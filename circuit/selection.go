package circuit

import (
	"math/rand"
	"slices"

	"github.com/robogg133/gonion/shared"
)

func SelectExitRelay(outPort uint16, consensus *shared.Consensus, getSTABLE bool) shared.RouterStatus {

	var filtered []shared.RouterStatus
	var filteredBW []int32
	var totalBandWidth uint64

	for _, v := range consensus.RelayInformation {
		if getSTABLE {
			if !v.StatusFlags[shared.FLAG_STABLE] {
				continue
			}
		}
		if v.StatusFlags[shared.FLAG_EXIT] && !v.StatusFlags[shared.FLAG_BAD_EXIT] && v.StatusFlags[shared.FLAG_RUNNING] && v.StatusFlags[shared.FLAG_VALID] && v.StatusFlags[shared.FLAG_FAST] && v.Ports.IsAllowed(outPort) {
			filtered = append(filtered, v)
			numToUse := consensus.BandWidthWeight.Wee

			if v.StatusFlags[shared.FLAG_GUARD] {
				numToUse = consensus.BandWidthWeight.Wed
			}
			calc := numToUse * int32(v.BandWidth)
			filteredBW = append(filteredBW, calc)

			totalBandWidth += uint64(calc)
		}
	}

	a := randUint64Range(1, totalBandWidth)
	x := int64(a)
	for i, v := range filteredBW {
		x -= int64(v)
		if x <= 0 {
			return filtered[i]
		}
	}
	return filtered[0]
}

func SelectGuardRelay(consensus *shared.Consensus, exitIPLevel uint32, ports ...uint16) shared.RouterStatus {
	var specifiedConnPort bool
	if len(ports) > 0 {
		specifiedConnPort = true
	}

	var filtered []shared.RouterStatus
	var filteredBW []int32
	var totalBandWidth uint64

	for _, v := range consensus.RelayInformation {
		if v.StatusFlags[shared.FLAG_GUARD] && v.IPLevel != exitIPLevel {
			if specifiedConnPort {
				if !slices.Contains(ports, v.ORPort) {
					continue
				}
			}

			filtered = append(filtered, v)
			numToUse := consensus.BandWidthWeight.Wgg

			if v.StatusFlags[shared.FLAG_EXIT] {
				numToUse = consensus.BandWidthWeight.Wgd
			}
			calc := numToUse * int32(v.BandWidth)
			filteredBW = append(filteredBW, calc)

			totalBandWidth += uint64(calc)
		}
	}

	a := randUint64Range(1, totalBandWidth)
	x := int64(a)

	for i, v := range filteredBW {
		x -= int64(v)
		if x <= 0 {
			return filtered[i]
		}
	}
	return filtered[0]
}

func SellectMiddleRelay(consensus *shared.Consensus, exitLvl, guardLvl uint32, getSTABLE bool) shared.RouterStatus {

	var filtered []shared.RouterStatus
	var filteredBW []int32
	var totalBandWidth uint64

	for _, v := range consensus.RelayInformation {
		if getSTABLE {
			if !v.StatusFlags[shared.FLAG_STABLE] {
				continue
			}
		}
		if v.StatusFlags[shared.FLAG_RUNNING] && v.StatusFlags[shared.FLAG_VALID] && v.StatusFlags[shared.FLAG_FAST] && v.IPLevel != exitLvl && v.IPLevel != guardLvl {
			filtered = append(filtered, v)
			numToUse := consensus.BandWidthWeight.Wmm

			if v.StatusFlags[shared.FLAG_GUARD] {
				numToUse = consensus.BandWidthWeight.Wmg
			}
			if v.StatusFlags[shared.FLAG_EXIT] {
				numToUse = consensus.BandWidthWeight.Wme
			}
			if v.StatusFlags[shared.FLAG_GUARD] && v.StatusFlags[shared.FLAG_EXIT] {
				numToUse = consensus.BandWidthWeight.Wmd
			}

			calc := numToUse * int32(v.BandWidth)
			filteredBW = append(filteredBW, calc)

			totalBandWidth += uint64(calc)
		}
	}

	a := randUint64Range(1, totalBandWidth)
	x := int64(a)
	for i, v := range filteredBW {
		x -= int64(v)
		if x <= 0 {
			return filtered[i]
		}
	}
	return filtered[0]
}

func randUint64Range(min, max uint64) uint64 {

	return min + uint64(rand.Int63n(int64(max-min)))
}
