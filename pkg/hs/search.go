package hs

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/crypto"
)

type routerStatsAndRelayIndex struct {
	relay *common.RouterStatus
	idx   [32]byte
}

// hsdirRing starts just after the service index and wraps at the end. Keeping
// pointers avoids copying each relay's 8 KiB exit-policy bitmap while sorting.
func hsdirRing(sharedSecret []byte, periodNum, periodLen uint64, list []common.RouterStatus, index crypto.HsServiceIndex) ([]*common.RouterStatus, error) {
	if len(sharedSecret) != 32 || len(index) != 32 || periodLen == 0 {
		return nil, fmt.Errorf("hs: invalid HSDir index inputs")
	}
	var ring []routerStatsAndRelayIndex
	for i := range list {
		r := &list[i]
		if !r.StatusFlags[common.FLAG_HIDDEN_SERVICE_DIR] || len(r.IdEd25519) != 32 || !r.ProtoVersions.HSDir.CheckIsTrue(common.VERSION_2) {
			continue
		}
		idx := crypto.RelayIndex(r.IdEd25519, sharedSecret, periodNum, periodLen)
		ring = append(ring, routerStatsAndRelayIndex{r, [32]byte(idx)})
	}
	if len(ring) == 0 {
		return nil, fmt.Errorf("hs: no HSDir=2 relays")
	}
	sort.Slice(ring, func(i, j int) bool { return bytes.Compare(ring[i].idx[:], ring[j].idx[:]) < 0 })
	start := sort.Search(len(ring), func(i int) bool { return bytes.Compare(ring[i].idx[:], index) > 0 })
	out := make([]*common.RouterStatus, len(ring))
	for i := range out {
		out[i] = ring[(start+i)%len(ring)].relay
	}
	return out, nil
}

// Search returns the default three responsible HSDirs for a single replica.
func Search(sharedSecret []byte, periodNum, periodLen uint64, list []common.RouterStatus, index crypto.HsServiceIndex) ([]common.RouterStatus, error) {
	ring, err := hsdirRing(sharedSecret, periodNum, periodLen, list, index)
	if err != nil {
		return nil, err
	}
	if len(ring) < 3 {
		return nil, fmt.Errorf("hs: not enough HSDirs")
	}
	out := make([]common.RouterStatus, 3)
	for i := range out {
		out[i] = *ring[i]
	}
	return out, nil
}
