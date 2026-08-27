// Package mem provides an in-memory consensus store.
package mem

import (
	"sync"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/storage"
)

type store struct {
	mu sync.RWMutex
	c  *common.Consensus
}

// New returns a storage.Storage that keeps a single consensus in memory.
func New() storage.Storage {
	return &store{}
}

func (s *store) StoreConsensus(c *common.Consensus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.c = c
	return nil
}

func (s *store) GetConsensus() (*common.Consensus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c, nil
}