package path

import (
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
)

func trustedTestConsensus(t *testing.T, now time.Time) *common.Consensus {
	t.Helper()
	input := testutil.Consensus(t, now)
	c, err := input.OwnAuthenticatedHydration(input.Microdescriptors)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSelectionUsesOnlyVerifiedDescriptorAndSignedFields(t *testing.T) {
	input := testutil.Consensus(t, time.Now()) // Signed offline microdesc consensus, Tor/Chutney descriptor fixture.
	c, err := input.OwnAuthenticatedHydration(input.Microdescriptors)
	if err != nil {
		t.Fatal(err)
	}
	original := c.Trusted()
	sel := New(c, false)
	c.RelayInformation[0].NodeID = [20]byte{99}
	c.RelayInformation[0].IdEd25519[0] ^= 1
	c.RelayInformation[0].Familys = []*common.FamilyIDs{{Kind: "ed25519", Value: []byte{1}}}
	c.RelayInformation[0].StatusFlags = [15]bool{}
	c.BandWidthWeight = common.BandWidthWeight{}
	c.ValidUntil = time.Now().Add(-time.Hour)
	c.Params = map[string]int32{"bwweightscale": 0}
	c.RawDocument[0] ^= 1
	c.Microdescriptors[original.RelayInformation[0].MicrodescriptorDigest][0] ^= 1
	if !c.IsLive(time.Now()) || !c.TrustedHydrated() {
		t.Fatal("public mutation disabled authentic state")
	}
	if _, err := c.OwnAuthenticatedHydration(c.Microdescriptors); err == nil {
		t.Fatal("modified descriptor was accepted")
	}
	for _, source := range []*common.Consensus{c, c.Clone()} {
		s := New(source, false)
		if err := s.SelectRandomCircuit(3, 443); err != nil {
			t.Fatal(err)
		}
		guard := s.Guard()
		guard.IdEd25519[0] ^= 1
		guard.Familys = []*common.FamilyIDs{{Kind: "ed25519", Value: []byte{1}}}
		path := s.Circuit()
		path[0].NodeID = [20]byte{88}
		if s.Guard().NodeID == [20]byte{88} || s.Guard().IdEd25519[0] == guard.IdEd25519[0] {
			t.Fatal("relay result aliases selection")
		}
		for _, r := range s.Circuit() {
			if r.NodeID == [20]byte{99} || r.NodeID == [20]byte{88} {
				t.Fatal("mutated relay selected")
			}
		}
	}
	if err := sel.SelectRandomCircuit(3, 443); err != nil {
		t.Fatal(err)
	}
}
