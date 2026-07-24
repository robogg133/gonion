package path_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/path"
)

func mustPub(t *testing.T) *ecdh.PublicKey {
	t.Helper()
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sk.PublicKey()
}

func testRelay(t *testing.T, nick string, flags ...uint8) common.RouterStatus {
	t.Helper()
	var f [common.FLAG_ARRAY_LENGTH + 1]bool
	f[common.FLAG_RUNNING] = true
	f[common.FLAG_VALID] = true
	for _, fl := range flags {
		f[fl] = true
	}
	var ports common.Ports
	ports.SetPort(80, true)
	ports.SetPort(443, true)

	var nodeID [20]byte
	copy(nodeID[:], []byte(nick))
	return common.RouterStatus{
		Nickname:     nick,
		NodeID:       nodeID,
		Ipv4Addr:     "1.2.3.4",
		ORPort:       9001,
		IPLevel:      uint32(len(nick)), // unique-ish
		BandWidth:    1000,
		StatusFlags:  f,
		Ports:        ports,
		NTorOnionKey: mustPub(t),
		IdEd25519:    make([]byte, 32),
	}
}

func TestSelectRandomCircuit_ThreeHop(t *testing.T) {
	cns := &common.Consensus{
		RelayInformation: []common.RouterStatus{
			testRelay(t, "guard1", common.FLAG_GUARD, common.FLAG_FAST, common.FLAG_STABLE, common.FLAG_V2DIR),
			testRelay(t, "guard2", common.FLAG_GUARD, common.FLAG_FAST, common.FLAG_STABLE, common.FLAG_V2DIR),
			testRelay(t, "mid1", common.FLAG_FAST),
			testRelay(t, "mid2", common.FLAG_FAST),
			testRelay(t, "exit1", common.FLAG_EXIT, common.FLAG_FAST),
			testRelay(t, "exit2", common.FLAG_EXIT, common.FLAG_FAST),
		},
		BandWidthWeight: common.BandWidthWeight{
			Wgg: 10000, Wgd: 10000, Wee: 10000, Wed: 10000, Wmm: 10000, Wmg: 10000, Wmd: 10000,
		},
	}
	// Unique IP levels already via nick length — make them truly unique.
	for i := range cns.RelayInformation {
		cns.RelayInformation[i].IPLevel = uint32(i + 1)
		cns.RelayInformation[i].Ipv4Addr = "1.2.3." + string(rune('1'+i))
	}

	sl := path.New(cns, false)
	if err := sl.SelectRandomCircuit(3, 80); err != nil {
		t.Fatal(err)
	}
	if sl.Guard() == nil || sl.Exit() == nil || len(sl.Middle()) != 1 {
		t.Fatalf("path incomplete: guard=%v mid=%d exit=%v", sl.Guard(), len(sl.Middle()), sl.Exit())
	}
	if len(sl.Circuit()) != 3 {
		t.Fatalf("circuit len=%d", len(sl.Circuit()))
	}
	if sl.Circuit()[0] != sl.Guard() || sl.Circuit()[2] != sl.Exit() {
		t.Fatal("circuit order")
	}
}

func TestSelectRandomCircuit_NoEligibleExit(t *testing.T) {
	cns := &common.Consensus{
		RelayInformation: []common.RouterStatus{
			testRelay(t, "guard1", common.FLAG_GUARD, common.FLAG_FAST, common.FLAG_STABLE, common.FLAG_V2DIR),
		},
	}
	sl := path.New(cns, false)
	err := sl.SelectRandomCircuit(3, 80)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSelectRandomCircuit_ZeroWeightConsensusStillWorks(t *testing.T) {
	// All consensus weights zero — should fall back to raw bandwidth.
	cns := &common.Consensus{
		RelayInformation: []common.RouterStatus{
			testRelay(t, "g1", common.FLAG_GUARD, common.FLAG_FAST, common.FLAG_STABLE, common.FLAG_V2DIR),
			testRelay(t, "m1", common.FLAG_FAST),
			testRelay(t, "e1", common.FLAG_EXIT, common.FLAG_FAST),
		},
	}
	for i := range cns.RelayInformation {
		cns.RelayInformation[i].IPLevel = uint32(i + 10)
	}
	sl := path.New(cns, false)
	if err := sl.SelectRandomCircuit(3, 80); err != nil {
		t.Fatal(err)
	}
}
