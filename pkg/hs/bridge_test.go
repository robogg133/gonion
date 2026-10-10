package hs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

type bridgeBuilder struct {
	serviceBuildFunc
	guard *common.RouterStatus
	err   error
}

func (b bridgeBuilder) CircuitGuard(context.Context) (*common.RouterStatus, error) {
	return b.guard, b.err
}

// All client/service circuit purposes converge here. Test both randomly chosen
// rendezvous relays and explicit descriptor/introduction/publication targets.
func TestOnionCircuitPurposesKeepBridge(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	guard := cns.RelayInformation[0]
	guard.NodeID, guard.Ipv4Addr = [20]byte{99}, "192.0.2.1"
	for _, purpose := range []string{"client rendezvous", "descriptor fetch", "client introduction", "service introduction", "service publication", "service rendezvous"} {
		t.Run(purpose, func(t *testing.T) {
			builds := 0
			b := bridgeBuilder{guard: &guard, serviceBuildFunc: func(_ context.Context, relays []*common.RouterStatus) (capi.Circ, error) {
				builds++
				if len(relays) != 3 || relays[0].NodeID != guard.NodeID {
					t.Fatal("bridge replaced or extra hop inserted")
				}
				if builds == 1 {
					return nil, errors.New("retry on same bridge")
				}
				ctx, cancel := context.WithCancel(context.Background())
				return &lifecycleCircuit{ctx: ctx, cancel: cancel}, nil
			}}
			var target *common.RouterStatus
			if purpose != "client rendezvous" {
				target = &cns.RelayInformation[5]
			}
			circ, err := buildCircuitWithRetry(context.Background(), b, cns, 3, 0, target)
			if err != nil {
				t.Fatal(err)
			}
			_ = circ.Close()
			if builds != 2 {
				t.Fatal("did not retry path")
			}
			b.err = errors.New("bridge descriptor expired")
			if _, err := buildCircuitWithRetry(context.Background(), b, cns, 3, 0, target); !errors.Is(err, b.err) || builds != 2 {
				t.Fatal("guard error bypassed")
			}
		})
	}
}
