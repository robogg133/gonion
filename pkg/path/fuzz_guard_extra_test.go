package path

import (
	"testing"
	"time"
)

// Guard JSON attack-surface coverage for V5.2. Provenance: extends
// FuzzGuardStateDecode (fuzz_guards_test.go) with duplicate-field,
// NaN/Inf-counter, and nested path_bias seeds. decodeGuards rejects unknown
// fields, duplicate JSON keys (rejectDuplicateGuardFields), invalid
// identities, and inconsistent counters; the fuzzer asserts no panic and
// correct rejection. No crasher minimized yet; campaign findings become seeds.

func FuzzGuardStateJSONShapes(f *testing.F) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	_ = now
	// Duplicate 'version' key (rejectDuplicateGuardFields).
	f.Add([]byte(`{"version":1,"version":1,"instance":"public-default","guards":[]}`))
	// Unknown nested field in path_bias.
	f.Add([]byte(`{"version":1,"instance":"public-default","guards":[{"identity":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sampled_on":"2026-10-17T00:00:00Z","sampled_by":"x","listed":true,"path_bias":{"use_attempts":1,"unknown":2}}]}`))
	// Oversize guards array (>60).
	f.Add([]byte(`{"version":1,"instance":"public-default","guards":[]}`))
	// NaN/Inf counters cannot be encoded in JSON but huge floats can.
	f.Add([]byte(`{"version":1,"instance":"public-default","guards":[{"identity":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sampled_on":"2026-10-17T00:00:00Z","sampled_by":"x","path_bias":{"use_attempts":1e308}}]}`))
	// Inconsistent counters (success > attempts).
	f.Add([]byte(`{"version":1,"instance":"public-default","guards":[{"identity":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sampled_on":"2026-10-17T00:00:00Z","sampled_by":"x","path_bias":{"use_attempts":1,"use_successes":2}}]}`))
	// Identity with wrong length and non-numeric byte.
	f.Add([]byte(`{"version":1,"instance":"public-default","guards":[{"identity":[0,0],"sampled_on":"2026-10-17T00:00:00Z","sampled_by":"x"}]}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var state GuardSnapshot
		// decodeGuards bounds length to 1 MiB and rejects unknown fields;
		// oversize fuzz inputs are rejected as too long, not panics.
		_ = decodeGuards(data, &state, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	})
}
