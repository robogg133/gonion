package common

import (
	"testing"
	"time"
)

// rend-spec-v3 2.2.1 gives this example, including the noon rotation offset.
func TestTimePeriodSpecExample(t *testing.T) {
	at := time.Date(2016, 4, 13, 11, 15, 1, 0, time.UTC)
	c := &Consensus{ValidAfter: at, FreshUntil: at.Add(time.Hour)}
	if c.CalcPeriodNum() != 16903 || c.CalcPeriodLength() != 1440 {
		t.Fatalf("period=%d length=%d", c.CalcPeriodNum(), c.CalcPeriodLength())
	}
}

func TestCalcPeriodNum(t *testing.T) {
	// Typical consensus: valid-after 22:00, fresh-until 23:00, no hsdir-interval.
	validAfter := time.Date(2026, 1, 30, 22, 0, 0, 0, time.UTC)
	cns := &Consensus{
		ValidAfter: validAfter,
		FreshUntil: validAfter.Add(time.Hour),
	}

	if got := cns.CalcSrvVotingInterval(); got != 60 {
		t.Fatalf("voting interval = %d, want 60", got)
	}
	if got := cns.CalcRotationTimeOffset(); got != 60*12*60 {
		t.Fatalf("rotation offset = %d, want %d", got, 60*12*60)
	}
	if got := cns.CalcPeriodLength(); got != HsdirIntervalDefaultValue {
		t.Fatalf("period length = %d, want %d", got, HsdirIntervalDefaultValue)
	}

	want := (uint64(validAfter.Unix()) - 60*12*60) / (HsdirIntervalDefaultValue * 60)
	if got := cns.CalcPeriodNum(); got != want {
		t.Fatalf("period num = %d, want %d", got, want)
	}
}
