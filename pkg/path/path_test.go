package path

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
)

func TestSelectRandomCircuit(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	if cns.BandWidthWeight.Wgg != 10000 || cns.BandWidthWeight.Wme != 10000 {
		t.Fatal("missing consensus weights were not defaulted")
	}
	sl := New(cns, false)
	if err := sl.SelectRandomCircuit(3, 80); err != nil {
		t.Fatal(err)
	}
	if sl.Guard() == nil || sl.Exit() == nil || len(sl.Middle()) != 1 || len(sl.Circuit()) != 3 {
		t.Fatal("incomplete path")
	}
	if sl.Circuit()[0] != sl.Guard() || sl.Circuit()[2] != sl.Exit() {
		t.Fatal("incorrect circuit order")
	}
	for i, a := range sl.Circuit() {
		for _, b := range sl.Circuit()[i+1:] {
			if sl.relaysConflict(a, b) {
				t.Fatal("conflicting relays selected")
			}
		}
	}
	// No Exit candidates: test the filter without weakening New's trust gate.
	sl.list = cns.RelayInformation[:2]
	if err := sl.SelectRandomCircuit(3, 80); err == nil {
		t.Fatal("selected path with no eligible exit")
	}
}

func TestSelectionRequiresAuthenticatedLiveConsensus(t *testing.T) {
	now := time.Now()
	for name, cns := range map[string]*common.Consensus{
		"nil":       nil,
		"untrusted": {ValidAfter: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)},
		"expired":   testutil.Consensus(t, now.Add(-24*time.Hour)),
		"future":    testutil.Consensus(t, now.Add(24*time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			sl := New(cns, false)
			if err := sl.SelectRandomCircuit(3, 80); err == nil {
				t.Fatal("untrusted or non-live consensus selected a path")
			}
			if _, err := sl.SelectHSRelay(true); err == nil {
				t.Fatal("untrusted or non-live consensus selected an intro relay")
			}
			target := testutil.Consensus(t, now).RelayInformation[0]
			if err := sl.SelectCircuitTo(1, &target); err == nil {
				t.Fatal("explicit target bypassed consensus validation")
			}
		})
	}
}

func TestConsensusWeights(t *testing.T) {
	// path-spec 2.2 / dir-spec 3.4.1; C Tor node_select.c uses Wme, and
	// treats BadExit as a non-exit for both positional and directory weights.
	weights := common.BandWidthWeight{Wgg: 1, Wgd: 2, Wmm: 3, Wmg: 4, Wme: 5, Wmd: 6, Wmb: 7, Wgb: 8, Web: 9, Wdb: 10}
	for _, tc := range []struct {
		guard, exit, bad   bool
		middle, dir, entry int64
	}{
		{false, false, false, 3, 7, 1},
		{true, false, false, 4, 8, 1},
		{false, true, false, 5, 9, 2},
		{true, true, false, 6, 10, 2},
		{false, true, true, 3, 7, 1},
		{true, true, true, 4, 8, 1},
	} {
		var flags [15]bool
		flags[common.FLAG_GUARD], flags[common.FLAG_EXIT], flags[common.FLAG_BAD_EXIT] = tc.guard, tc.exit, tc.bad
		if middleWeightFunc(flags, weights) != tc.middle || directoryWeight(flags, weights) != tc.dir || guardWeightFunc(flags, weights) != tc.entry {
			t.Fatalf("wrong weighting for %+v", tc)
		}
	}
	if weightedBandwidth(1000, 0) != 0 || weightedBandwidth(0, 10000) != 0 || weightedBandwidth(1, 1) != 1000 {
		t.Fatal("zero or small positive weight changed")
	}
	if weightedBandwidth(^uint32(0), 1<<31-1) != int64(1<<31-1)*int64(1<<31-1) {
		t.Fatal("C Tor bandwidth cap not applied")
	}
	sl := New(testutil.Consensus(t, time.Now()), false)
	sl.weight.Wgg, sl.weight.Wgd = 0, 0
	if err := sl.SelectRandomCircuit(3, 80); err == nil {
		t.Fatal("explicit zero guard weights fell back to bandwidth")
	}
	sl.weight.Wgg, sl.weight.Wgd = 10000, 10000
	sl.weight.Wgb = 0
	if err := sl.SelectRandomCircuit(3, 80); err == nil {
		t.Fatal("explicit zero BEGIN_DIR multiplier ignored")
	}
	// Legal scale products can exceed uint64. Selection must not overflow.
	var total big.Int
	values := make([]value, 2)
	for i := range values {
		values[i].ptr = &sl.list[i]
		values[i].wb.Exp(big.NewInt(1<<31-1), big.NewInt(3), nil)
		total.Add(&total, &values[i].wb)
	}
	if _, err := selectRandom(&total, values); err != nil {
		t.Fatal(err)
	}
}

func TestRelayDiversity(t *testing.T) {
	// Identities and nicknames from C Tor test_nodelist_node_nodefamily,
	// commit 3937194. Family membership must be mutual, not transitive.
	a := common.RouterStatus{Nickname: "nodeone", Ipv4Addr: "10.1.1.1"}
	b := common.RouterStatus{Nickname: "nodetwo", Ipv4Addr: "10.2.1.1"}
	copy(a.NodeID[:], "NodeOneNode1NodeOne1")
	copy(b.NodeID[:], "SecondNodeWe'reTestn")
	sl := &Selector{}
	check := func(want bool) {
		t.Helper()
		if sl.relaysConflict(&a, &b) != want || sl.relaysConflict(&b, &a) != want {
			t.Fatalf("symmetric conflict = %v, want %v", sl.relaysConflict(&a, &b), want)
		}
	}
	check(false)
	a.Family = []common.Family{{Digest: b.NodeID[:]}}
	check(false)
	b.Family = []common.Family{{Digest: a.NodeID[:]}}
	check(true)
	a.Family = []common.Family{{Nickname: "NODETWO"}}
	check(true)
	a.Family, b.Family = []common.Family{{Nickname: "nodethree"}}, []common.Family{{Nickname: "nodethree"}}
	check(false)
	a.Family, b.Family = nil, nil
	b.Ipv4Addr = "10.1.255.254"
	b.IPLevel = 999 // A forged cached prefix cannot bypass the real address.
	check(true)
	b.Ipv4Addr = "10.2.1.1"
	a.Ipv6Addr, b.Ipv6Addr = "[2001:db8:1::1]:9001", "[2001:db8:ffff::1]:9001"
	check(true) // C Tor router_addrs_in_same_network: IPv6 /32.
	b.Ipv6Addr = "[2001:db9::1]:9001"
	check(false)
	id := bytes.Repeat([]byte{1}, 32)
	a.Familys, b.Familys = []*common.FamilyIDs{{Kind: "ed25519", Value: id}}, []*common.FamilyIDs{{Kind: "ed25519", Value: bytes.Clone(id)}}
	check(true)
	a.Familys, b.Familys = nil, nil
	a.IdEd25519, b.IdEd25519 = id, bytes.Clone(id)
	check(true)
	a.IdEd25519, b.IdEd25519 = nil, nil
	b.NodeID = a.NodeID
	check(true)
}

func TestExplicitTargetKeepsFamilyAndWireMetadata(t *testing.T) {
	sl := New(testutil.Consensus(t, time.Now()), true)
	a, b := &sl.list[0], &sl.list[5]
	a.Family = []common.Family{{Digest: b.NodeID[:]}}
	b.Family = []common.Family{{Digest: a.NodeID[:]}}
	target := *b
	target.Family = nil // A descriptor/INTRODUCE2 contains no family list.
	target.LinkSpecifiers = []byte{1, 99, 1, 42}
	if err := sl.SelectCircuitTo(3, &target); err != nil {
		t.Fatal(err)
	}
	if sl.Guard().NodeID == a.NodeID || len(sl.Exit().Family) == 0 || !bytes.Equal(sl.Exit().LinkSpecifiers, target.LinkSpecifiers) || sl.Exit().NTorOnionKey != target.NTorOnionKey {
		t.Fatal("target family lost or authenticated wire metadata replaced")
	}
	if len(target.Family) != 0 {
		t.Fatal("selector mutated caller target")
	}
	target.IdEd25519 = bytes.Repeat([]byte{7}, 32)
	if err := sl.SelectCircuitTo(3, &target); err == nil {
		t.Fatal("conflicting relay identity accepted")
	}
}

func TestConflictsFilteredBeforeWeightedSelection(t *testing.T) {
	sl := New(testutil.Consensus(t, time.Now()), false)
	// One overwhelming but conflicting candidate must not exhaust a retry
	// budget and hide the only eligible guard (path-spec 2.2).
	sl.list[0].BandWidth = ^uint32(0)
	sl.list[1].BandWidth = 1
	sl.exit = &sl.list[0]
	for i := 0; i < 10; i++ {
		r, err := sl.selectRelay(guardValideFunc, guardWeightFunc, 0)
		if err != nil || r != &sl.list[1] {
			t.Fatalf("eligible low-bandwidth guard lost: %v", err)
		}
	}
}
