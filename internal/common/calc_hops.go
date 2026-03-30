package common

import (
	"math/rand"
	"slices"
)

func SelectExitRelay(outPort uint16, consensus *Consensus, getSTABLE bool) *RouterStatus {

	var filtered []*RouterStatus
	var filteredBW []int32
	var totalBandWidth uint64

	for _, v := range consensus.RelayInformation {
		if getSTABLE {
			if !v.StatusFlags[FLAG_STABLE] {
				continue
			}
		}
		if v.StatusFlags[FLAG_EXIT] && !v.StatusFlags[FLAG_BAD_EXIT] && v.StatusFlags[FLAG_RUNNING] && v.StatusFlags[FLAG_VALID] && v.StatusFlags[FLAG_FAST] && v.Ports.IsAllowed(outPort) {
			filtered = append(filtered, &v)
			numToUse := consensus.BandWidthWeight.Wee

			if v.StatusFlags[FLAG_GUARD] {
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

func SelectGuardRelay(consensus *Consensus, exitIPLevel uint32, ports ...uint16) *RouterStatus {
	var specifiedConnPort bool
	if len(ports) > 0 {
		specifiedConnPort = true
	}

	var filtered []*RouterStatus
	var filteredBW []int32
	var totalBandWidth uint64

	for _, v := range consensus.RelayInformation {
		if v.StatusFlags[FLAG_GUARD] && v.IPLevel != exitIPLevel {
			if specifiedConnPort {
				if !slices.Contains(ports, v.ORPort) {
					continue
				}
			}

			filtered = append(filtered, &v)
			numToUse := consensus.BandWidthWeight.Wgg

			if v.StatusFlags[FLAG_EXIT] {
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

func SellectMiddleRelay(consensus *Consensus, exitLvl, guardLvl uint32, getSTABLE bool) *RouterStatus {

	var filtered []*RouterStatus
	var filteredBW []int32
	var totalBandWidth uint64

	for _, v := range consensus.RelayInformation {
		if getSTABLE {
			if !v.StatusFlags[FLAG_STABLE] {
				continue
			}
		}
		if v.StatusFlags[FLAG_RUNNING] && v.StatusFlags[FLAG_VALID] && v.StatusFlags[FLAG_FAST] && v.IPLevel != exitLvl && v.IPLevel != guardLvl {
			filtered = append(filtered, &v)
			numToUse := consensus.BandWidthWeight.Wmm

			if v.StatusFlags[FLAG_GUARD] {
				numToUse = consensus.BandWidthWeight.Wmg
			}
			if v.StatusFlags[FLAG_EXIT] {
				numToUse = consensus.BandWidthWeight.Wme
			}
			if v.StatusFlags[FLAG_GUARD] && v.StatusFlags[FLAG_EXIT] {
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
