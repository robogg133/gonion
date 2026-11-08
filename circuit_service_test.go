package gonion

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/internal/window"
	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/crypto"
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

// fillTestPattern writes a deterministic per-element pattern so byte slices
// are individually recognizable after the crawl through the relay layers.
func fillTestPattern(b []byte, row byte) {
	for i := range b {
		b[i] = row + byte(i)
	}
}

// TestJoinRendezvous1LegacyPayload168Bytes drives JoinRendezvous through the
// real relay-framing path and asserts the encoded RENDEZVOUS1 payload against
// rend-spec-v3 4.3: rendezvous cell payloads must be exactly 168 bytes long,
// padded with random bytes like C Tor's hs_circ_service_rp_has_opened pads
// the 84-byte cell (20-byte cookie + 64-byte ntor reply) up to
// HS_LEGACY_RENDEZVOUS_CELL_SIZE. The cookie and the first 64 bytes of the
// relayed HANDSHAKE_INFO must be unchanged.
func TestJoinRendezvous1LegacyPayload168Bytes(t *testing.T) {
	// Validated test-only onion address (see pkg/hs/onion/onion_test.go).
	const serviceAddr = "tbup4alxvo3wmessgrbjfbfpny6x5xab56do6sli6i6b42sgreisrfqd.onion:80"

	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(net.ErrClosed) })
	writeCall := make(chan cellWrite, 4)
	frames := make(chan cellWrite, 4)
	c := &Circuit{
		conn:      &Conn{writeCall: writeCall, ctx: ctx, ctxCancel: cancel},
		Coder:     cells.NewCellCoder(nil),
		Ctx:       ctx,
		ctxCancel: cancel,
		streams:   &streams{streams: make(map[uint16]*Stream)},
	}
	go func() {
		for cell := range writeCall {
			frames <- cell
			cell.done <- nil
		}
	}()

	// JoinRendezvous marshals RENDEZVOUS1 for the last physical hop and
	// layered-encrypts it through hops 2..0, all of which must return real
	// hop state. The virtual e2e hop is appended by JoinRendezvous itself.
	// The asserted cell is the circuit's first cell, so every hop keystream
	// is consumed exactly once from its initial counter.
	fwdKeys := [3][16]byte{}
	fwdSeeds := [3][32]byte{}
	for i := range fwdKeys {
		fillTestPattern(fwdKeys[i][:], byte(i))
		fillTestPattern(fwdSeeds[i][:], byte(64+i))
		back, err := crypto.NewRunningValues(fwdKeys[i][:], fwdSeeds[i][:])
		if err != nil {
			t.Fatal(err)
		}
		// Same key material for the backward direction is fine here: the
		// test never feeds cells into the circuit, so only forward sending
		// state is used.
		c.hops.Append(hops.NewHop(ctx, relay.NewDataCellCoder(back, back),
			window.NewWindow(1000, 100), window.NewWindow(1000, 100)))
	}

	var cookie [20]byte
	for i := range cookie {
		cookie[i] = byte(1 + i)
	}
	reply := make([]byte, 64)
	for i := range reply {
		reply[i] = byte(0x40 + i)
	}
	var kf, kb, df, db [32]byte
	fillTestPattern(kf[:], 0x80)
	fillTestPattern(kb[:], 0x90)
	fillTestPattern(df[:], 0xA0)
	fillTestPattern(db[:], 0xB0)
	if err := c.JoinRendezvous(cookie, reply, kf[:], kb[:], df[:], db[:], serviceAddr); err != nil {
		t.Fatalf("JoinRendezvous: %v", err)
	}
	linkCell := <-frames
	close(writeCall)

	// Fixed-size link frame: 5-byte header + 509-byte relay body (tor-spec
	// 3 for negotiated link versions 4+).
	if len(linkCell.data) != 514 {
		t.Fatalf("link cell is %d bytes, want 514", len(linkCell.data))
	}
	if cmd := linkCell.data[4]; cmd != cells.COMMAND_RELAY {
		t.Fatalf("link command %d, want RELAY", cmd)
	}
	plain := make([]byte, 509)
	copy(plain, linkCell.data[5:])
	for i := 0; i < 3; i++ {
		nv, err := crypto.NewRunningValues(fwdKeys[i][:], fwdSeeds[i][:])
		if err != nil {
			t.Fatal(err)
		}
		nv.XORKeyStream(plain, plain)
	}

	if plain[0] != relay.COMMAND_RENDEZVOUS1 {
		t.Fatalf("relay command %d, want RENDEZVOUS1 (%d)", plain[0], relay.COMMAND_RENDEZVOUS1)
	}
	if plain[1] != 0 || plain[2] != 0 {
		t.Fatal("recognized field not zero before the final physical hop")
	}
	if id := binary.BigEndian.Uint16(plain[3:5]); id != 0 {
		t.Fatalf("stream ID %d, want zero (rendezvous is a control cell)", id)
	}
	// The digest was stamped by the last physical hop over the payload with
	// a zeroed digest field; reproduce it with a fresh running value.
	digest := bytes.Clone(plain[5:9])
	digestFrame := bytes.Clone(plain)
	clear(digestFrame[5:9])
	digestNV, err := crypto.NewRunningValues(fwdKeys[2][:], fwdSeeds[2][:])
	if err != nil {
		t.Fatal(err)
	}
	if err := digestNV.Write(digestFrame); err != nil {
		t.Fatal(err)
	}
	if expected := digestNV.Sum(); !bytes.Equal(expected[:4], digest) {
		t.Fatal("relay digest does not match the payload contents")
	}
	// rend-spec-v3 4.3 / C Tor hs_common.h: HS_LEGACY_RENDEZVOUS_CELL_SIZE.
	if payloadLen := int(binary.BigEndian.Uint16(plain[9:11])); payloadLen != 168 {
		t.Fatalf("RENDEZVOUS1 payload is %d bytes, want exactly 168", payloadLen)
	}
	prefix := append(append(make([]byte, 0, 84), cookie[:]...), reply...)
	if !bytes.Equal(plain[11:11+len(prefix)], prefix) {
		t.Fatal("cookie or 64-byte handshake reply altered before the padding")
	}
	// rend-spec-v3 4.3 / C Tor hs_circuit.c: the legacy padding is random,
	// never zero-padded.
	pad := plain[11+84 : 11+168]
	if !slices.ContainsFunc(pad, func(b byte) bool { return b != 0 }) {
		t.Fatal("legacy padding region is not random")
	}
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
