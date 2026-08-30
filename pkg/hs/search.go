package hs

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/crypto"
)

type routerStatsAndRelayIndex struct {
	common.RouterStatus
	idx *big.Int
}

func Search(sharedSecret []byte, periodNum, periodLen uint64, list []common.RouterStatus, index crypto.HsServiceIndex) ([]common.RouterStatus, error) {
	serviceIndex := new(big.Int).SetBytes(index)

	var filtered []routerStatsAndRelayIndex

	for _, relay := range list {
		if !relay.StatusFlags[common.FLAG_HIDDEN_SERVICE_DIR] {
			continue
		}
		// The hsdir_index uses the relay's ed25519 identity, not its (RSA) node
		// id (rend-spec-v3 §[HSDIR-INDEX]).
		identity := relay.IdEd25519
		if len(identity) == 0 {
			continue
		}

		filtered = append(filtered, routerStatsAndRelayIndex{
			RouterStatus: relay,
			idx:          new(big.Int).SetBytes(crypto.RelayIndex(identity, sharedSecret, periodNum, periodLen)),
		})
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("no relays with HSDir flag")
	}

	sort.Slice(filtered, func(i, j int) bool {
		idxI := filtered[i].idx
		idxJ := filtered[j].idx
		return idxI.Cmp(idxJ) == -1 // i < j
	})
	// filtered sorted ascending by hsdir_index

	var res []common.RouterStatus
	for _, fi := range filtered {
		if fi.idx.Cmp(serviceIndex) < 0 {
			continue
		}
		if len(res) == 3 {
			break
		}
		res = append(res, fi.RouterStatus)
	}

	if len(res) < 3 {
		return nil, fmt.Errorf("not enough hsdir relays for service index (found %d, need 3)", len(res))
	}

	return res, nil
}
