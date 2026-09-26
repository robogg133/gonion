package tests

import (
	"testing"
	"time"

	"github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/common"
)

func TestNextConsensusFetchTime_Window(t *testing.T) {
	t.Parallel()

	validAfter := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	freshUntil := time.Date(2026, 5, 23, 13, 0, 0, 0, time.UTC)
	validUntil := time.Date(2026, 5, 23, 15, 0, 0, 0, time.UTC)

	cns := &common.Consensus{
		ValidAfter: validAfter,
		FreshUntil: freshUntil,
		ValidUntil: validUntil,
	}

	// Sample many times from "before window".
	now := validAfter
	wantStart := freshUntil.Add(45 * time.Minute)      // +3/4 of 1h
	wantEnd := wantStart.Add(75 * time.Minute / 8 * 7) // +7/8 of the remaining 75m

	for range 50 {
		ft, err := gonion.NextConsensusFetchTimeForTest(cns, now)
		if err != nil {
			t.Fatal(err)
		}
		if ft.Before(wantStart) || !ft.Before(wantEnd) {
			t.Fatalf("fetch %s outside [%s, %s)", ft, wantStart, wantEnd)
		}
	}
}
