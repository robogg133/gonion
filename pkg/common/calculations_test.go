package common

import (
	"testing"
	"time"
)

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
	if got := cns.CalcPeriodLength(); got != HsdirIntervalDefaultValue*60 {
		t.Fatalf("period length = %d, want %d", got, HsdirIntervalDefaultValue*60)
	}

	want := (uint64(validAfter.Unix()) - 60*12*60) / (HsdirIntervalDefaultValue * 60)
	if got := cns.CalcPeriodNum(); got != want {
		t.Fatalf("period num = %d, want %d", got, want)
	}
}
