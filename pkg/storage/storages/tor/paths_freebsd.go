//go:build freebsd

package tor

import "os"

// DefaultDataDir is the C Tor default data directory. It is exposed only for
// callers that deliberately want that legacy location; Gonion does not select
// it automatically.
const DefaultDataDir = "/var/lib/tor"

// syncDirectory persists directory entries on platforms that support it.
func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
