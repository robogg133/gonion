// Package tor provides a consensus store that persists the consensus on disk
// the same way the tor C binary does: <DataDir>/cached-consensus.
package tor

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/robogg133/gonion/pkg/common"
	jsonparser "github.com/robogg133/gonion/pkg/parsers/json"
	"github.com/robogg133/gonion/pkg/storage"
)

const cachedConsensusFile = "cached-consensus"

type store struct {
	dir string
}

// New returns a consensus store rooted at dir.
// An empty dir selects the platform default tor data directory.
func New(dir string) storage.Storage {
	if dir == "" {
		dir = defaultDataDir()
	}
	return &store{dir: dir}
}

func (s *store) StoreConsensus(c *common.Consensus) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}

	b, err := (jsonparser.Parser{}).Format(c)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(s.dir, cachedConsensusFile), b, 0o600)
}

func (s *store) GetConsensus() (*common.Consensus, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, cachedConsensusFile))
	if err != nil {
		return nil, err
	}

	return (jsonparser.Parser{}).Parse(bytes.NewReader(b))
}