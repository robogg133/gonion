package tests

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestCalc(t *testing.T) {

	validAfter := time.Date(2026, 05, 23, 12, 0, 0, 0, time.UTC)
	freshUntil := time.Date(2026, 05, 23, 13, 0, 0, 0, time.UTC)
	validUntil := time.Date(2026, 05, 23, 15, 0, 0, 0, time.UTC)

	fmt.Printf("valid-after %s\n", validAfter.Format("2006-01-2 15:04:05"))
	fmt.Printf("fresh-until %s\n", freshUntil.Format("2006-01-2 15:04:05"))
	fmt.Printf("valid-until %s\n", validUntil.Format("2006-01-2 15:04:05"))

	minutesBetweenFreshAndValid := (freshUntil.Hour() - validAfter.Hour()) * 60

	minutes := (time.Duration(minutesBetweenFreshAndValid) / 4) * 3
	start := freshUntil.Add(minutes * time.Minute)

	minutesBetweenFreshAndUnvalid := (validUntil.Hour() - freshUntil.Hour()) * 60
	minutes = (time.Duration(minutesBetweenFreshAndUnvalid) / 8) * 7
	end := freshUntil.Add(minutes * time.Minute)

	ns := start.Unix()
	ne := end.Unix()
	fmt.Printf("START TIMESTAMP: %d END TIMETAMP: %d\n", ns, ne)

	fetchTimestamp := rand.Int63n(ne-ns) + ns

	fetchTime := time.Unix(fetchTimestamp, 0).UTC()

	fmt.Printf("random between %s and %s : %s\n", start.Format("2006-01-02 15:04:05"), end.Format("2006-01-02 15:04:05"), fetchTime.Format("2006-01-02 15:04:05"))

}
