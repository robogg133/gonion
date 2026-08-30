package gonion

import (
	"context"
	"net"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

// The adapters below implement pkg/hs/capi interfaces over the concrete
// *gonion.Circuit / *gonion.Conn so that pkg/hs (which must not import
// pkg/gonion to avoid an import cycle) can drive hidden-service operations.

func (c *Circuit) SetHSControl(ch chan relay.Cell) {
	c.HSControl = ch
}

// RecvHSControl blocks until an HS control cell arrives on the registered
// HSControl channel, or the circuit/context is cancelled.
func (c *Circuit) RecvHSControl(ctx context.Context) (relay.Cell, error) {
	if c.HSControl == nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.Ctx.Done():
			return nil, c.Ctx.Err()
		}
	}
	select {
	case cell := <-c.HSControl:
		return cell, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.Ctx.Done():
		return nil, c.Ctx.Err()
	}
}

type circAdapter struct{ c *Circuit }

func (a circAdapter) HopCount() int { return a.c.HopCount() }

func (a circAdapter) Ctx() context.Context { return a.c.Ctx }

func (a circAdapter) NewStream(target string, hopDest int) (capi.Stream, error) {
	s, err := a.c.NewStream(target, hopDest)
	if err != nil {
		return nil, err
	}
	return streamAdapter{s}, nil
}

func (a circAdapter) SendHSControl(cell relay.Cell) error { return a.c.SendHSControl(cell) }

func (a circAdapter) SetHSControl(ch chan relay.Cell) { a.c.SetHSControl(ch) }

func (a circAdapter) RecvHSControl(ctx context.Context) (relay.Cell, error) {
	return a.c.RecvHSControl(ctx)
}

func (a circAdapter) AppendE2EHop(Kf, Kb, Df, Db []byte) error {
	return a.c.AppendE2EHop(Kf, Kb, Df, Db)
}

func (a circAdapter) Close() error { return a.c.Close() }

// NewCircAdapter wraps a *Circuit as a capi.Circ.
func NewCircAdapter(c *Circuit) capi.Circ { return circAdapter{c} }

type streamAdapter struct{ s *Stream }

func (s streamAdapter) SendCell(cell relay.Cell) error { return s.s.SendCell(cell) }

func (s streamAdapter) Recv(ctx context.Context) (relay.Cell, error) {
	select {
	case cell := <-s.s.InboundControl:
		return cell, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.s.Ctx.Done():
		return nil, s.s.Ctx.Err()
	}
}

func (s streamAdapter) Conn() net.Conn { return s.s.Conn() }
func (s streamAdapter) Free() error    { return s.s.Free() }

type connBuilder struct{ conn *Conn }

func (b connBuilder) BuildPath(id uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	circ, err := b.conn.BuildPath(id, relays)
	if err != nil {
		return nil, err
	}
	return circAdapter{circ}, nil
}

// NewConnBuilder wraps a *Conn as a capi.CircuitBuilder.
func NewConnBuilder(conn *Conn) capi.CircuitBuilder { return connBuilder{conn} }
