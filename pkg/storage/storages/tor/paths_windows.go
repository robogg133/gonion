//go:build windows

package tor

import (
	"os"
	"path/filepath"
)

// DefaultDataDir is the tor data directory used by the tor C binary on Windows.
// The %APPDATA% marker is expanded in defaultDataDir.
const DefaultDataDir = "%APPDATA%\\Tor"

func defaultDataDir() string {
	return filepath.Join(os.Getenv("APPDATA"), "Tor")
}