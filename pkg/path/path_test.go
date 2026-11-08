package path

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
)

// path-spec 6: a configured bridge replaces, rather than precedes, the guard.
func TestFixedBridgeSelection(t *testing.T) {
	cns := trustedTestConsensus(t, time.Now())
	bridge := cns.RelayInformation[0]
	bridge.NodeID, bridge.Ipv4Addr = [20]byte{99}, "192.0.2.1"
	bridge.StatusFlags = [15]bool{}
	for i := 0; i < 20; i++ {
		sel := NewWithGuard(cns, true, &bridge)
		if err := sel.SelectRandomCircuit(3, 443); err != nil {
			t.Fatal(err)
		}
		if len(sel.Circuit()) != 3 || sel.Guard().NodeID != bridge.NodeID {
			t.Fatal("bridge was replaced or an extra hop was added")
		}
		for _, hop := range sel.Circuit()[1:] {
			if sel.relaysConflict(&bridge, hop) {
				t.Fatal("bridge diversity was ignored")
			}
		}
		target, err := sel.SelectHSRelay(true)
		if err != nil {
			t.Fatal(err)
		}
		if err := sel.SelectCircuitTo(3, target); err != nil {
			t.Fatal(err)
		}
		if sel.Guard().NodeID != bridge.NodeID || sel.Exit().NodeID != target.NodeID {
			t.Fatal("explicit target path lost bridge or target")
		}
	}
	sel := NewWithGuard(cns, false, &bridge)
	if err := sel.SelectCircuitTo(3, &bridge); err == nil {
		t.Fatal("bridge used twice")
	}
	bridge.Ipv4Addr = cns.RelayInformation[5].Ipv4Addr
	sel = NewWithGuard(cns, false, &bridge)
	if err := sel.SelectCircuitTo(3, &cns.RelayInformation[5]); err == nil {
		t.Fatal("same-network target accepted")
	}
	bridge.NTorOnionKey = nil
	sel = NewWithGuard(cns, false, &bridge)
	if err := sel.SelectRandomCircuit(3, 443); err == nil {
		t.Fatal("missing bridge key fell back to public guard")
	}
}

func TestSelectRandomCircuit(t *testing.T) {
	cns := trustedTestConsensus(t, time.Now())
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
	if sl.Circuit()[0].NodeID != sl.Guard().NodeID || sl.Circuit()[2].NodeID != sl.Exit().NodeID {
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
		"expired":   trustedTestConsensus(t, now.Add(-24*time.Hour)),
		"future":    trustedTestConsensus(t, now.Add(24*time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			sl := New(cns, false)
			if err := sl.SelectRandomCircuit(3, 80); err == nil {
				t.Fatal("untrusted or non-live consensus selected a path")
			}
			if _, err := sl.SelectHSRelay(true); err == nil {
				t.Fatal("untrusted or non-live consensus selected an intro relay")
			}
			target := trustedTestConsensus(t, now).RelayInformation[0]
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
	sl := New(trustedTestConsensus(t, time.Now()), false)
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
	sl := New(testutil.ConsensusWithFamily(t, time.Now(), 0, 5), true)
	a, b := &sl.list[0], &sl.list[5]
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
	sl := New(trustedTestConsensus(t, time.Now()), false)
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

// path-spec §2.2 / dir-spec §3.4.1 adversarial weight vectors: an explicitly
// signed zero or negative weight is authoritative (it excludes the position's
// candidates instead of falling back to raw bandwidth), malformed
// consensus-parameter scales clamp before use, and legal-scale products that
// exceed 64 bits stay in big.Int arithmetic.
func TestAdversarialWeightHandling(t *testing.T) {
	t.Run("negative-middle-weights-exclude-candidates", func(t *testing.T) {
		sl := New(trustedTestConsensus(t, time.Now()), false)
		sl.weight.Wmm, sl.weight.Wmg, sl.weight.Wme, sl.weight.Wmd = -1, -1, -1, -1
		if err := sl.SelectRandomCircuit(3, 80); err == nil {
			t.Fatal("negative middle weights fell back to bandwidth")
		}
	})
	t.Run("negative-guard-weights-exclude-candidates", func(t *testing.T) {
		sl := New(trustedTestConsensus(t, time.Now()), false)
		sl.weight.Wgg, sl.weight.Wgd = -1, -1
		if err := sl.SelectRandomCircuit(3, 80); err == nil {
			t.Fatal("negative guard weights fell back to bandwidth")
		}
	})
	t.Run("negative-exit-weights-exclude-candidates", func(t *testing.T) {
		sl := New(trustedTestConsensus(t, time.Now()), false)
		sl.weight.Wee, sl.weight.Wed = -1, -1
		if err := sl.SelectRandomCircuit(3, 80); err == nil {
			t.Fatal("negative exit weights fell back to bandwidth")
		}
	})
	t.Run("zero-wme-drops-exit-only-middles", func(t *testing.T) {
		var flags [15]bool
		flags[common.FLAG_EXIT] = true
		weights := common.BandWidthWeight{Wmm: 10000, Wmg: 10000, Wme: 0, Wmd: 10000}
		if middleWeightFunc(flags, weights) != 0 {
			t.Fatal("explicit zero Wme ignored")
		}
	})
	t.Run("bwweightscale-clamps-to-positive", func(t *testing.T) {
		sl := New(trustedTestConsensus(t, time.Now()), false)
		sl.consensus.Params = map[string]int32{"bwweightscale": -7}
		for i := range sl.list {
			sl.list[i].StatusFlags[common.FLAG_V2DIR] = false
		}
		r, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0)
		if err != nil || r == nil {
			t.Fatalf("unclamped bwweightscale excluded every candidate: %v", err)
		}
	})
	t.Run("overflow-scale-values", func(t *testing.T) {
		sl := New(trustedTestConsensus(t, time.Now()), false)
		sl.list[0].BandWidth = ^uint32(0)
		sl.weight.Wmm, sl.weight.Wmg, sl.weight.Wme, sl.weight.Wmd = 1<<30, 1<<30, 1<<30, 1<<30
		for i := 0; i < 10; i++ {
			if _, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0); err != nil {
				t.Fatalf("overflow-scale pick failed: %v", err)
			}
		}
	})
}

// path-spec §2.2.1: BadExit and missing-Exit relays are never exit candidates,
// and a relay missing authenticated keys is never a candidate for any position.
func TestForbiddenExitValidationVectors(t *testing.T) {
	cns := trustedTestConsensus(t, time.Now())
	base := cns.RelayInformation[0]
	var plain [15]bool
	exitOnly := base
	exitOnly.StatusFlags = plain
	exitOnly.StatusFlags[common.FLAG_EXIT] = true
	if !exitValidateFunc(exitOnly) {
		t.Fatal("plain exit rejected")
	}
	badExit := exitOnly
	badExit.StatusFlags[common.FLAG_BAD_EXIT] = true
	if exitValidateFunc(badExit) {
		t.Fatal("BadExit accepted as exit")
	}
	noExit := base
	noExit.StatusFlags = plain
	if exitValidateFunc(noExit) {
		t.Fatal("non-Exit accepted as exit")
	}
	keyless := exitOnly
	keyless.NTorOnionKey = nil
	if exitValidateFunc(keyless) || middleValideFunc(keyless) {
		t.Fatal("keyless relay accepted")
	}
	guard := base
	guard.StatusFlags = plain
	guard.StatusFlags[common.FLAG_GUARD], guard.StatusFlags[common.FLAG_FAST] = true, true
	guard.StatusFlags[common.FLAG_STABLE], guard.StatusFlags[common.FLAG_V2DIR] = true, true
	if !guardValideFunc(guard) {
		t.Fatal("guard-spec GUARDS flags rejected")
	}
	for _, flag := range []uint8{common.FLAG_GUARD, common.FLAG_FAST, common.FLAG_STABLE, common.FLAG_V2DIR} {
		guard.StatusFlags = plain
		guard.StatusFlags[common.FLAG_GUARD], guard.StatusFlags[common.FLAG_FAST] = true, true
		guard.StatusFlags[common.FLAG_STABLE], guard.StatusFlags[common.FLAG_V2DIR] = true, true
		guard.StatusFlags[flag] = false
		if guardValideFunc(guard) {
			t.Fatalf("guard accepted without flag %d", flag)
		}
	}
	// Selector level: a sole BadExit candidate cannot carry an exit position.
	sl := New(cns, false)
	allPorts := [65536 / 8]byte{}
	for i := range allPorts {
		allPorts[i] = 0xFF
	}
	sl.list[0].StatusFlags = plain
	sl.list[0].StatusFlags[common.FLAG_EXIT] = true
	sl.list[0].StatusFlags[common.FLAG_BAD_EXIT] = true
	sl.list[0].StatusFlags[common.FLAG_RUNNING], sl.list[0].StatusFlags[common.FLAG_VALID] = true, true
	sl.list[0].Ports = allPorts
	sl.list = sl.list[:1]
	if _, err := sl.SelectTail(443); err == nil {
		t.Fatal("BadExit selected as exit")
	}
	sl.list[0].StatusFlags[common.FLAG_BAD_EXIT] = false
	if _, err := sl.SelectTail(443); err != nil {
		t.Fatalf("eligible exit rejected: %v", err)
	}
}

// path-spec §2.2: exit policies gate exit positions only. An empty policy
// rejects every port at an exit position, while a port-0 tail (HS circuits)
// never consults exit policy at all.
func TestPortPolicySelectionVectors(t *testing.T) {
	sl := New(trustedTestConsensus(t, time.Now()), false)
	relay := sl.list[0]
	relay.StatusFlags = [15]bool{}
	relay.StatusFlags[common.FLAG_EXIT] = true
	relay.StatusFlags[common.FLAG_RUNNING], relay.StatusFlags[common.FLAG_VALID] = true, true
	relay.Ports = [65536 / 8]byte{} // reject *:*
	sl.list = []common.RouterStatus{relay}
	if _, err := sl.SelectTail(443); err == nil {
		t.Fatal("exit with rejecting policy selected")
	}
	allPorts := [65536 / 8]byte{}
	for i := range allPorts {
		allPorts[i] = 0xFF
	}
	sl.list[0].Ports = allPorts
	if r, err := sl.SelectTail(443); err != nil || r == nil {
		t.Fatalf("policy-allowing exit rejected: %v", err)
	}
	// Port 0 selects a non-exit final hop without consulting policy.
	sl.list[0].Ports = [65536 / 8]byte{}
	sl.list[0].StatusFlags[common.FLAG_EXIT] = false
	if r, err := sl.SelectTail(0); err != nil || r == nil {
		t.Fatalf("port-0 tail wrongly policy-gated: %v", err)
	}
}

// path-spec §2.2 stable/running requirements: long-lived selection keeps only
// Stable relays, ordinary selection keeps all of them, and no selection ever
// returns a non-Running or non-Valid relay.
func TestStableAndRunningFlagVectors(t *testing.T) {
	cns := trustedTestConsensus(t, time.Now())
	unstable := func(sl *Selector) {
		for i := range sl.list {
			sl.list[i].StatusFlags[common.FLAG_STABLE] = false
		}
	}
	sl := New(cns, true)
	for i := 1; i < len(sl.list); i++ {
		sl.list[i].StatusFlags[common.FLAG_STABLE] = false
	}
	r, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0)
	if err != nil || r != &sl.list[0] {
		t.Fatalf("long-lived pick %v, want the only stable relay: %v", r, err)
	}
	sl = New(cns, false)
	unstable(sl)
	if _, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0); err != nil {
		t.Fatalf("unstable relay excluded without long-live: %v", err)
	}
	sl = New(cns, true)
	unstable(sl)
	if _, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0); err == nil {
		t.Fatal("long-lived selection returned a non-Stable relay")
	}
	sl = New(cns, false)
	for i := range sl.list {
		sl.list[i].StatusFlags[common.FLAG_RUNNING] = false
	}
	if _, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0); err == nil {
		t.Fatal("non-Running relay selected")
	}
	sl = New(cns, false)
	for i := range sl.list {
		sl.list[i].StatusFlags[common.FLAG_VALID] = false
	}
	if _, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0); err == nil {
		t.Fatal("non-Valid relay selected")
	}
}

// Selection must refuse an authenticated but unhydrated consensus: parsed
// signature state without digest-bound relay keys is not usable directory
// state (D2.4 "never uses unauthenticated state").
func TestSelectionRejectsUnhydratedConsensus(t *testing.T) {
	input := testutil.Consensus(t, time.Now())
	// Rebuild the same signed fixture through AuthenticateConsensus only —
	// the state a client holds after signature verification but before
	// OwnAuthenticatedHydration has bound relay keys to descriptor digests.
	// The authority pin comes from the fixture certificate, the same value
	// internal/testutil pins (sha1 over the PKCS#1 identity key).
	const marker = "fingerprint "
	certs := string(input.AuthorityCertificates)
	idx := strings.Index(certs, marker)
	if idx < 0 {
		t.Fatal("fixture certificate missing fingerprint")
	}
	line := certs[idx+len(marker):]
	if nl := strings.IndexAny(line, "\r\n"); nl >= 0 {
		line = line[:nl]
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(line))
	if err != nil || len(decoded) != 20 {
		t.Fatalf("fixture authority fingerprint: %v", err)
	}
	var pin [20]byte
	copy(pin[:], decoded)
	auth, err := common.AuthenticateConsensus(input.RawDocument, input.AuthorityCertificates, [][20]byte{pin}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !auth.IsAuthenticated() || auth.TrustedHydrated() {
		t.Fatal("fixture must be authenticated and unhydrated")
	}
	sl := New(auth, false)
	if _, err := sl.selectRelay(middleValideFunc, middleWeightFunc, 0); err == nil {
		t.Fatal("unhydrated consensus supplied selection candidates")
	}
	if err := sl.SelectRandomCircuit(3, 443); err == nil {
		t.Fatal("unhydrated consensus built a path")
	}
}
