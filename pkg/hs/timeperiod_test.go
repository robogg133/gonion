package hs

import "testing"

// rend-spec §TIME-PERIODS worked example:
//
//	ts = 1460546101 (2016-04-13 11:15:01 Z)  ->  period 16903,
//	period began 1460469600 (2016-04-12 12:00:00 Z), length 1440 min.
func TestPeriodVector(t *testing.T) {
	const ts = 1460546101
	const periodLen = 1440

	n := PeriodNum(ts, periodLen, DefaultRotationOffsetMinutes)
	if n != 16903 {
		t.Fatalf("PeriodNum = %d, want 16903", n)
	}
	start := PeriodStart(n, periodLen, DefaultRotationOffsetMinutes)
	if start != 1460462400 {
		t.Fatalf("PeriodStart = %d, want 1460462400", start)
	}
}

func TestPeriodDefaults(t *testing.T) {
	if PeriodNum(0, 0, -1) != 0 {
		t.Fatal("expected period 0 just after epoch")
	}
	// 24h after rotation offset: still period 0 with 1440-min periods.
	if PeriodNum(DefaultPeriodLengthMinutes*60, DefaultPeriodLengthMinutes, DefaultRotationOffsetMinutes) >= 2 {
		t.Fatal("period too large")
	}
}
