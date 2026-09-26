package embed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

type contextTestBuilder struct {
	capi.CircuitBuilder
	circ capi.Circ
	ctx  context.Context
}

func (b *contextTestBuilder) BuildPathContext(ctx context.Context, _ uint32, _ []*common.RouterStatus) (capi.Circ, error) {
	b.ctx = ctx
	return b.circ, nil
}

func TestClientOwnsDedicatedCircuitLifetime(t *testing.T) {
	life, cancel := context.WithCancel(context.Background())
	defer cancel()
	circ := &blockingCirc{stubCirc: &stubCirc{hops: 3}, ctx: life, cancel: cancel}
	builder := &contextTestBuilder{circ: circ}
	c := newTestClient(t, builder)
	operation, finish, err := c.operationContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	owned := contextBuilder{ctx: operation, lifetime: c.lifetime, builder: builder}
	got, err := owned.BuildPath(1, nil)
	if err != nil || got != circ || builder.ctx != operation {
		t.Fatalf("context-aware builder not used: %v", err)
	}
	finish()
	if operation.Err() == nil || life.Err() != nil {
		t.Fatal("initialization context owns returned circuit lifetime")
	}
	_ = c.Close()
	select {
	case <-life.Done():
	case <-time.After(time.Second):
		t.Fatal("Client.Close left a dedicated onion circuit alive")
	}
}

func TestListenValidationAndClientCancellation(t *testing.T) {
	c := newTestClient(t, &stubBuilder{})
	if _, err := c.Listen(context.Background(), ServiceOptions{}); err == nil {
		t.Fatal("accepted missing caller identity/persistence policy")
	}
	opts := ServiceOptions{Identity: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), Port: 80, NextRevision: func(context.Context, [32]byte) (uint64, error) { return 1, nil }}
	if _, err := c.Listen(context.Background(), opts); err == nil {
		t.Fatal("accepted non-cancellable builder")
	}
	op, finish, err := c.operationContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	_ = c.Close()
	select {
	case <-op.Done():
	case <-time.After(time.Second):
		t.Fatal("pending operation not cancelled by Client.Close")
	}
	if _, err := c.Listen(context.Background(), opts); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Listen after Close: %v", err)
	}
}
