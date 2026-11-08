//go:build windows

package tor

// DefaultDataDir is the C Tor default data directory on Windows. It is exposed
// only for callers that deliberately want that legacy location; Gonion does not
// select it automatically.
const DefaultDataDir = "%APPDATA%\\Tor"

// syncDirectory is a no-op on Windows, where directory fsync is not available
// through this interface. File-level sync and atomic rename provide the best
// available durability.
func syncDirectory(dir string) error {
	_ = dir
	return nil
}
