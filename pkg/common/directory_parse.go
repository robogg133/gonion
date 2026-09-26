package common

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ReadAll rejects oversize input instead of treating a limit as a clean EOF.
func ReadDirectoryDocument(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("directory document exceeds %d bytes", limit)
	}
	return b, nil
}

// ParsePorts validates dir-spec 3.8.2 before calling the legacy bitmap parser.
func ParseDirectoryPorts(dst *Ports, s string) error {
	f := strings.Fields(s)
	if len(f) < 2 || (f[0] != "accept" && f[0] != "reject") || len(f[0])+1+len(f[1]) > 1000 {
		return fmt.Errorf("directory: invalid exit policy summary")
	}
	for _, item := range strings.Split(f[1], ",") {
		a, b, hasRange := strings.Cut(item, "-")
		start, err := strconv.ParseUint(a, 10, 16)
		if err != nil {
			return fmt.Errorf("directory: invalid policy port %q", item)
		}
		if hasRange {
			end, err := strconv.ParseUint(b, 10, 16)
			if err != nil || end < start {
				return fmt.Errorf("directory: invalid policy range %q", item)
			}
		}
	}
	if err := ParsePortsLine(dst, f[0]+" "+f[1]); err != nil {
		return err
	}
	dst.SetPort(0, false)
	return nil
}
