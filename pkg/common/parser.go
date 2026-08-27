package common

import "io"

const CONSENSUS_DATE_FORMAT = "2006-01-02 15:04:05"

// ConsensusParser parses and formats a network-status consensus document.
type ConsensusParser interface {
	Parse(r io.Reader) (*Consensus, error)
	Format(c *Consensus) ([]byte, error)
}

// MicrodescParser parses and formats microdescriptor documents.
type MicrodescParser interface {
	Parse(r io.Reader, digests []string) ([]*Microdesc, error)
	Format(ms []*Microdesc) ([]byte, error)
}