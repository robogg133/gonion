package path

import (
	"testing"
	"time"
)

func FuzzGuardStateDecode(f *testing.F) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	f.Add([]byte(`{"version":1,"instance":"public-default","guards":[],"last_valid_after":"2026-10-17T00:00:00Z"}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var state GuardSnapshot
		_ = decodeGuards(data, &state, now)
	})
}
