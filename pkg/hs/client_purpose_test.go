package hs

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/path"
)

// purposeWiringCircuit satisfies capi.Circ without touching link state.
type purposeWiringCircuit struct {
	ctx    context.Context
	closed int
}

func (c *purposeWiringCircuit) HopCount() int                              { return 3 }
func (c *purposeWiringCircuit) Ctx() context.Context                       { return c.ctx }
func (c *purposeWiringCircuit) NewStream(string, int) (capi.Stream, error) { return nil, net.ErrClosed }
func (c *purposeWiringCircuit) SendHSControl(relay.Cell) error             { return nil }
func (c *purposeWiringCircuit) SetHSControl(chan relay.Cell)               {}
func (c *purposeWiringCircuit) RecvHSControl(context.Context) (relay.Cell, error) {
	return nil, net.ErrClosed
}
func (c *purposeWiringCircuit) AppendE2EHop([]byte, []byte, []byte, []byte) error { return nil }
func (c *purposeWiringCircuit) Close() error {
	c.closed++
	return nil
}

type purposeWiringBuilder struct {
	guards *path.GuardManager
	circ   *purposeWiringCircuit
}

func (b *purposeWiringBuilder) PublicGuardManager() *path.GuardManager { return b.guards }
func (b *purposeWiringBuilder) BuildPath(_ uint32, _ []*common.RouterStatus) (capi.Circ, error) {
	return b.circ, nil
}

// path-spec §7 / circpathbias.c pathbias_should_count: client introduction
// circuits are excluded from path-bias counters, while guard confirmation and
// lease lifecycle still run.
func TestBuildCircuitWithRetrySkipsClientIntroCounters(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	var mu sync.Mutex
	var raw []byte
	m, err := path.NewGuardManager(context.Background(), path.GuardPersistence{
		Load: func(context.Context) ([]byte, error) { return bytes.Clone(raw), nil },
		Save: func(_ context.Context, data []byte) error {
			mu.Lock()
			raw = bytes.Clone(data)
			mu.Unlock()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	circ := &purposeWiringCircuit{ctx: context.Background()}
	b := &purposeWiringBuilder{guards: m, circ: circ}
	tail := &cns.RelayInformation[0]
	if got, err := buildCircuitWithRetry(context.Background(), b, cns, 3, 0, tail, path.PurposeClientIntro); err != nil || got == nil {
		t.Fatalf("build: %v", err)
	}
	mu.Lock()
	data := bytes.Clone(raw)
	mu.Unlock()
	if len(data) == 0 {
		t.Fatal("guard state was never persisted")
	}
	var snap path.GuardSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	for _, g := range snap.Guards {
		if g.Identity == tail.NodeID && g.PathBias != (path.GuardPathBias{}) {
			t.Fatalf("client intro counted against path bias: %+v", g.PathBias)
		}
	}
}
