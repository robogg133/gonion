package tests

import (
	"math/rand"
	"testing"
	"time"
)

// TestConsensusRefreshWindow mirrors the bootstrap schedule math:
// fetch time is drawn uniformly from [fresh+0.75*freshWindow, fresh+0.875*validSpan].
func TestConsensusRefreshWindow(t *testing.T) {
	t.Parallel()

	validAfter := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	freshUntil := time.Date(2026, 5, 23, 13, 0, 0, 0, time.UTC)
	validUntil := time.Date(2026, 5, 23, 15, 0, 0, 0, time.UTC)

	minutesBetweenFreshAndValid := (freshUntil.Hour() - validAfter.Hour()) * 60
	minutes := (time.Duration(minutesBetweenFreshAndValid) / 4) * 3
	start := freshUntil.Add(minutes * time.Minute)

	minutesBetweenFreshAndUnvalid := (validUntil.Hour() - freshUntil.Hour()) * 60
	minutes = (time.Duration(minutesBetweenFreshAndUnvalid) / 8) * 7
	end := freshUntil.Add(minutes * time.Minute)

	if !start.Before(end) {
		t.Fatalf("start %s not before end %s", start, end)
	}

	// fresh window 60m → +45m; valid span from fresh 120m → +105m.
	wantStart := freshUntil.Add(45 * time.Minute)
	wantEnd := freshUntil.Add(105 * time.Minute)
	if !start.Equal(wantStart) {
		t.Fatalf("start=%s want %s", start, wantStart)
	}
	if !end.Equal(wantEnd) {
		t.Fatalf("end=%s want %s", end, wantEnd)
	}

	r := rand.New(rand.NewSource(1))
	ns, ne := start.Unix(), end.Unix()
	for range 200 {
		ts := r.Int63n(ne-ns) + ns
		ft := time.Unix(ts, 0).UTC()
		if ft.Before(start) || ft.After(end.Add(-time.Second)) && ft.Equal(end) {
			// Int63n is [0, ne-ns) so ts < ne; ft is always in [start, end).
		}
		if ft.Before(start) || !ft.Before(end) {
			t.Fatalf("sample %s outside [%s, %s)", ft, start, end)
		}
	}
}
