//go:build darwin

package tor

import (
	"os"
	"path/filepath"
)

// DefaultDataDir is the tor data directory used by the tor C binary when running as root.
const DefaultDataDir = "/var/lib/tor"

func defaultDataDir() string {
	if os.Geteuid() == 0 {
		return DefaultDataDir
	}
	return filepath.Join(os.Getenv("HOME"), ".tor")
}