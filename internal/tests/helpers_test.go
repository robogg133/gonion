package tests

import "testing"

// skipIfShort skips live network tests when -short is set.
func skipIfShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
}
