package gonion

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

func testServiceCircuit(t *testing.T) *Circuit {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	acceptCtx, stop := context.WithCancel(ctx)
	c := &Circuit{Ctx: ctx, ctxCancel: cancel, streams: &streams{streams: make(map[uint16]*Stream)}, WriteRelayCell: make(chan RelayOut, 512), writeControl: make(chan RelayOut, 32), service: &serviceCircuitState{ctx: acceptCtx, cancel: stop, port: 80, address: "service.onion:80", incoming: make(chan *Stream, 16)}}
	// Crypto is covered by the Appendix G.1 tests. These tests exercise the
	// stream state machine at the recognized-cell boundary (tor-spec 6.2).
	c.hops.Hops = make([]*hops.Hop, 4)
	t.Cleanup(func() { cancel(net.ErrClosed) })
	return c
}

func TestIncomingServiceStreamLifecycle(t *testing.T) {
	c := testServiceCircuit(t)
	c.acceptIncomingBegin(&relay.BeginCell{StreamID: 42, Addrport: ":80"}, 3)
	acceptedStream := c.streams.Get(42)
	if acceptedStream == nil {
		t.Fatal("valid BEGIN not queued")
	}
	// tor-spec 6.2 permits optimistic DATA before CONNECTED.
	if err := acceptedStream.writeDataCell(&relay.DataCell{Payload: []byte("optimistic")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := c.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out := <-c.WriteRelayCell; out.Cell.ID() != relay.COMMAND_CONNECTED || out.Cell.GetStreamID() != 42 || out.Dst != 3 {
		t.Fatal("CONNECTED was not first in the stream FIFO")
	}
	buf := make([]byte, 10)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "optimistic" {
		t.Fatalf("optimistic data: %q %v", buf, err)
	}
	c.acceptIncomingBegin(&relay.BeginCell{StreamID: 43, Addrport: ":80"}, 3)
	pending := c.streams.Get(43)
	_ = c.StopAccepting()
	if acceptedStream.Ctx.Err() != nil || c.Ctx.Err() != nil || pending.Ctx.Err() == nil {
		t.Fatal("StopAccepting did not preserve only the accepted stream")
	}
	if _, err := c.AcceptStream(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept after stop: %v", err)
	}
	_ = conn.Close()
	if c.Ctx.Err() == nil {
		t.Fatal("last accepted stream did not release stopped rendezvous")
	}
}

func TestIncomingBeginValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		id     uint16
		target string
		hop    int
		fatal  bool
	}{
		{"zero ID", 0, ":80", 3, true},
		{"wrong hop", 1, ":80", 2, true},
		{"wrong port", 1, ":81", 3, false},
		{"bad address", 1, "bad", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testServiceCircuit(t)
			c.acceptIncomingBegin(&relay.BeginCell{StreamID: tc.id, Addrport: tc.target}, tc.hop)
			if (c.Ctx.Err() != nil) != tc.fatal || len(c.service.incoming) != 0 {
				t.Fatal("invalid BEGIN accepted or incorrect circuit failure")
			}
			if !tc.fatal {
				if out := <-c.writeControl; out.Cell.ID() != relay.COMMAND_RELAY_END || out.Cell.GetStreamID() != tc.id {
					t.Fatal("missing END for rejected virtual port")
				}
			}
		})
	}
	c := testServiceCircuit(t)
	c.acceptIncomingBegin(&relay.BeginCell{StreamID: 9, Addrport: ":81"}, 3)
	c.acceptIncomingBegin(&relay.BeginCell{StreamID: 9, Addrport: ":80"}, 3)
	if c.Ctx.Err() == nil {
		t.Fatal("reused rejected stream ID")
	}
	c = testServiceCircuit(t)
	c.service = nil
	c.acceptIncomingBegin(&relay.BeginCell{StreamID: 1, Addrport: ":80"}, 3)
	if c.Ctx.Err() == nil {
		t.Fatal("accepted BEGIN on a client/intro circuit")
	}
}

func TestIncomingBeginQueueBound(t *testing.T) {
	c := testServiceCircuit(t)
	for id := uint16(1); id <= 17; id++ {
		c.acceptIncomingBegin(&relay.BeginCell{StreamID: id, Addrport: ":80"}, 3)
	}
	if len(c.service.incoming) != 16 || c.streams.Get(17) != nil || c.Ctx.Err() != nil {
		t.Fatal("incoming queue was not bounded or overflow killed accepted streams")
	}
	_ = c.StopAccepting()
	if c.Ctx.Err() == nil {
		t.Fatal("stopped idle service circuit remained alive")
	}
}
