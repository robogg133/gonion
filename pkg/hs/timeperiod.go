package hs

// Time-period math, rend-spec §TIME-PERIODS.
//
//	minutes_since_epoch = unix / 60
//	minutes_since_epoch -= ROTATION_OFFSET
//	period_num = minutes_since_epoch / period_len
//	start      = (period_num*period_len + ROTATION_OFFSET) * 60
//
// ROTATION_OFFSET defaults to 12 voting periods (= 720 min for 1h votes).

// DefaultRotationOffsetMinutes is 12 voting periods (12 * 60).
const DefaultRotationOffsetMinutes = 12 * 60

// DefaultPeriodLengthMinutes is the consensus default for hsdir-interval.
const DefaultPeriodLengthMinutes = 24 * 60

// PeriodNum returns the hidden-service time-period number for the given unix
// time, period length (minutes) and rotation offset (minutes).
func PeriodNum(now int64, periodLenMin, rotationOffsetMin int) uint64 {
	if periodLenMin <= 0 {
		periodLenMin = DefaultPeriodLengthMinutes
	}
	if rotationOffsetMin < 0 {
		rotationOffsetMin = DefaultRotationOffsetMinutes
	}
	minutes := now / 60
	minutes -= int64(rotationOffsetMin)
	if minutes < 0 {
		return 0
	}
	return uint64(minutes / int64(periodLenMin))
}

// PeriodStart returns the unix time (seconds) at which the given period began.
func PeriodStart(periodNum uint64, periodLenMin, rotationOffsetMin int) int64 {
	if periodLenMin <= 0 {
		periodLenMin = DefaultPeriodLengthMinutes
	}
	rot := periodLenOfOff(rotationOffsetMin)
	return int64(periodNum)*int64(periodLenMin)*60 + int64(rot)*60
}

func periodLenOfOff(m int) int {
	if m < 0 {
		return DefaultRotationOffsetMinutes
	}
	return m
}
