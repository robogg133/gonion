package embed

import (
	"context"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/internal/testutil/guardfixture"
	"github.com/robogg133/gonion/pkg/common"
)

func TestPoolUsesOwnedConsensusEvenWhenPublicViewChanges(t *testing.T) {
	signed := testutil.Consensus(t, time.Now())
	owned, err := signed.OwnAuthenticatedHydration(signed.Microdescriptors)
	if err != nil {
		t.Fatal(err)
	}
	b := &stubBuilder{}
	c := &Client{cns: owned, builder: testGuardBuilder{CircuitBuilder: b, guards: guardfixture.Manager(t)}}
	defer c.Close()
	pc, err := c.allocateCircuit(context.Background(), 80)
	if err != nil {
		t.Fatal(err)
	}
	pc.active = false
	owned.ValidUntil = time.Now().Add(-time.Hour)
	owned.RelayInformation[0].NodeID = [20]byte{99}
	owned.BandWidthWeight = common.BandWidthWeight{}
	again, err := c.allocateCircuit(context.Background(), 80)
	if err != nil || again != pc || b.built != 1 {
		t.Fatalf("public mutation altered pool trust: %v", err)
	}
	c.cns = &common.Consensus{ValidAfter: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
	if _, err := c.allocateCircuit(context.Background(), 80); err == nil {
		t.Fatal("untrusted pool reuse")
	}
}
