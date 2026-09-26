// Package usual parses Tor ns and microdesc consensus text.
package usual

import (
	"io"

	"github.com/robogg133/gonion/pkg/common"
)

type Parser struct{}

// Parse checks document structure, not authority signatures.
func (Parser) Parse(r io.Reader) (*common.Consensus, error) {
	return common.ParseConsensus(r)
}

// Format preserves the signed document without synthesizing signatures.
func (Parser) Format(c *common.Consensus) ([]byte, error) {
	return common.FormatConsensus(c)
}
