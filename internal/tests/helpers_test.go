package tests

import (
	"os"
	"testing"
)

// skipIfShort keeps public-network tests explicitly opt-in.
func skipIfShort(t *testing.T) {
	t.Helper()
	if testing.Short() || os.Getenv("GONION_NETWORK_TESTS") != "1" {
		t.Skip("set GONION_NETWORK_TESTS=1 and omit -short for live Tor tests")
	}
}
