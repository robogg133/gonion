package storage

import (
	"github.com/robogg133/gonion/pkg/common"
)

type Storage interface {
	StoreConsensus(*common.Consensus) error
	GetConsensus() (*common.Consensus, error)
}
