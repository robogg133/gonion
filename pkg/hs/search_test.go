package hs_test

import (
	"sort"
	"testing"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs"
	"github.com/robogg133/gonion/pkg/hs/crypto"
)

// TestSearchKeysOffEd25519Identity verifies that HSDir selection uses the
// relay's ed25519 identity, not its (RSA) node id, per rend-spec-v3
// §[HSDIR-INDEX]. All relays share one NodeID but carry distinct ed25519 ids:
// if Search used NodeID their indices would be identical/tied; using ed25519
// yields a deterministic, ascending selection.
func TestSearchKeysOffEd25519Identity(t *testing.T) {
	const (
		shared = iota // a single shared-random value byte
		periodNum
		periodLen
	)
	srv := [32]byte{byte(shared + 1)}

	var relays []common.RouterStatus
	for i := 0; i < 12; i++ {
		ed := make([]byte, 32)
		ed[0] = byte(i + 1)
		relays = append(relays, common.RouterStatus{
			Nickname:  "r",
			NodeID:    [20]byte{0xAA, 0xBB}, // same RSA id for every relay
			IdEd25519: ed,                   // distinct ed25519 id each
			StatusFlags: [common.FLAG_ARRAY_LENGTH + 1]bool{
				common.FLAG_HIDDEN_SERVICE_DIR: true,
			},
		})
	}

	// Oracle: relays sorted by ed25519-based index, then take the first 3
	// whose index is >= the service index.
	type rci struct {
		rs  common.RouterStatus
		idx []byte
	}
	oracle := make([]rci, 0, len(relays))
	for _, r := range relays {
		oracle = append(oracle, rci{rs: r, idx: crypto.RelayIndex(r.IdEd25519, srv[:], periodNum, periodLen)})
	}
	sort.Slice(oracle, func(i, j int) bool { return string(oracle[i].idx) < string(oracle[j].idx) })

	// service_index uses a fixed blinded-style index; any 32-byte value works.
	sindex := make([]byte, 32)
	sindex[0] = 0x80
	want := make([]*common.RouterStatus, 0, 3)
	for _, o := range oracle {
		if string(o.idx) < string(sindex) {
			continue
		}
		want = append(want, &o.rs)
		if len(want) == 3 {
			break
		}
	}
	if len(want) < 3 {
		t.Fatalf("oracle found <3 relays >= index")
	}

	got, err := hs.Search(srv[:], periodNum, periodLen, relays, sindex)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Search returned %d relays, want 3", len(got))
	}
	for i := range want {
		if got[i].Nickname != want[i].Nickname ||
			string(got[i].IdEd25519) != string(want[i].IdEd25519) {
			t.Fatalf("relay %d mismatch: got ed=%x want ed=%x", i, got[i].IdEd25519, want[i].IdEd25519)
		}
	}
}
