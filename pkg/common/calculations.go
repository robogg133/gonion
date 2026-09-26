package common

import "time"

const (
	HsdirIntervalDefaultValue = 1440
)

// CalcSrvVotingInterval returns the voting interval in minutes
// (fresh_until - valid_after).
func (cns *Consensus) CalcSrvVotingInterval() uint64 {
	minutes := cns.FreshUntil.Sub(cns.ValidAfter) / time.Minute
	if minutes <= 0 {
		return 60
	}
	return uint64(minutes)
}

// CalcRotationTimeOffset returns the SRV publish offset in seconds:
// 12 voting periods (rend-spec-v3 [TIME-PERIODS]).
func (cns *Consensus) CalcRotationTimeOffset() uint64 {
	return cns.CalcSrvVotingInterval() * 12 * 60
}

// CalcPeriodLength returns minutes, as required by HS key blinding and indexes.
func (cns *Consensus) CalcPeriodLength() uint64 {
	interval := uint64(HsdirIntervalDefaultValue)
	if cns.HsdirInterval != nil && *cns.HsdirInterval > 0 {
		interval = *cns.HsdirInterval
	}
	return min(14400, max(30, interval))
}

// CalcPeriodNum returns TP = floor((valid_after - srv_publish_offset) / period_length),
// all in seconds.
func (cns *Consensus) CalcPeriodNum() uint64 {
	offset := cns.CalcRotationTimeOffset()
	seconds := cns.ValidAfter.Unix()
	if seconds <= 0 {
		return 0
	}
	unix := uint64(seconds)
	if unix <= offset {
		return 0
	}
	return (unix - offset) / (cns.CalcPeriodLength() * 60)
}
