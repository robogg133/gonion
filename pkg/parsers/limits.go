// Package parsers contains shared bounds for directory document parsers.
package parsers

import (
	"io"

	"github.com/robogg133/gonion/pkg/common"
)

func ReadAll(r io.Reader, limit int64) ([]byte, error) {
	return common.ReadDirectoryDocument(r, limit)
}

func ParsePorts(dst *common.Ports, s string) error {
	return common.ParseDirectoryPorts(dst, s)
}
