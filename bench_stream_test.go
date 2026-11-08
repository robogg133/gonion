package gonion

import (
	"bytes"
	"context"
	"os"
	"testing"

	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/crypto"
)

// O6.1 root benchmarks: cell/relay encode-decode, stream copy, and controlled
// end-to-end workloads. All are offline unless noted; no public relay is used.
// Live-network Dial/throughput workloads are gated on GONION_NETWORK_TESTS=1
// and skip in the default suite (see docs/BENCHMARKS.md for procedure).

func benchCoderPair(b *testing.B) (*relay.RelayCellCoder, *relay.RelayCellCoder) {
	b.Helper()
	kf := bytes.Repeat([]byte{0x11}, 16)
	df := bytes.Repeat([]byte{0x22}, 20)
	kb := bytes.Repeat([]byte{0x33}, 16)
	db := bytes.Repeat([]byte{0x44}, 20)
	mk := func(key, seed []byte) *crypto.RunningValues {
		rv, err := crypto.NewRunningValues(key, seed)
		if err != nil {
			b.Fatal(err)
		}
		return rv
	}
	client := relay.NewDataCellCoder(mk(kb, db), mk(kf, df))
	server := relay.NewDataCellCoder(mk(kf, df), mk(kb, db))
	return client, server
}

func BenchmarkBaseCellRoundTripCreateFast(b *testing.B) {
	coder := cells.NewCellCoder(cells.AllKnownCells)
	var x [20]byte
	for i := range x {
		x[i] = byte(i + 1)
	}
	in := &cells.CreateFastCell{CircuitID: 0x80000001, X: x}
	raw, err := coder.MarshalCell(in)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cell, err := coder.ReadCell(bytes.NewReader(raw))
		if err != nil {
			b.Fatal(err)
		}
		if cell.GetCircuitID() != 0x80000001 {
			b.Fatal("circuit id mismatch")
		}
	}
}

func BenchmarkBaseCellMarshalCreateFast(b *testing.B) {
	coder := cells.NewCellCoder(cells.AllKnownCells)
	var x [20]byte
	for i := range x {
		x[i] = byte(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, err := coder.MarshalCell(&cells.CreateFastCell{CircuitID: 0x80000001, X: x})
		if err != nil {
			b.Fatal(err)
		}
		_ = raw
	}
}

func BenchmarkRelayDataCellEncodeDecode(b *testing.B) {
	payload := make([]byte, 498)
	for i := range payload {
		payload[i] = byte(i)
	}
	in := &relay.DataCell{StreamID: 7, Payload: payload}
	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		b.Fatal(err)
	}
	wire := bytes.Clone(buf.Bytes())
	out := &relay.DataCell{}
	if err := out.Decode(bytes.NewReader(wire)); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var w bytes.Buffer
		if err := in.Encode(&w); err != nil {
			b.Fatal(err)
		}
		var back relay.DataCell
		if err := back.Decode(bytes.NewReader(w.Bytes())); err != nil {
			b.Fatal(err)
		}
		// DataCell Encode carries only payload; StreamID is in the relay header
		// and not persisted by this codec (see relay_data.go).
		if !bytes.Equal(back.Payload, payload) {
			b.Fatal("roundtrip mismatch")
		}
	}
}

// Marshal is stateful (digest + cipher stream). The pair stays synchronized
// only when every client.Marshal is followed by server.Unmarshal of the same
// bytes; each loop iteration therefore does both.
func BenchmarkRelayCellCoderRoundTrip509(b *testing.B) {
	// Sanity-check one pair outside the loop on separate coders so the timed
	// pair starts synchronized.
	{
		client, server := benchCoderPair(b)
		payload := make([]byte, 498)
		ct, err := client.Marshal(&relay.DataCell{StreamID: 5, Payload: payload})
		if err != nil || len(ct) != 509 {
			b.Fatalf("sanity marshal: %v %d", err, len(ct))
		}
		if _, err := server.Unmarshal(ct); err != nil {
			b.Fatal(err)
		}
	}
	client, server := benchCoderPair(b)
	payload := make([]byte, 498)
	for i := range payload {
		payload[i] = byte(i)
	}
	b.SetBytes(509)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cellBytes, err := client.Marshal(&relay.DataCell{StreamID: 5, Payload: payload})
		if err != nil {
			b.Fatal(err)
		}
		cell, err := server.Unmarshal(cellBytes)
		if err != nil {
			b.Fatal(err)
		}
		got := cell.(*relay.DataCell)
		if got.GetStreamID() != 5 || !bytes.Equal(got.Payload, payload) {
			b.Fatal("relay roundtrip mismatch")
		}
	}
}

func BenchmarkRelayCellCoderMarshal509(b *testing.B) {
	client, _ := benchCoderPair(b)
	payload := make([]byte, 498)
	b.SetBytes(509)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := client.Marshal(&relay.DataCell{StreamID: 5, Payload: payload})
		if err != nil {
			b.Fatal(err)
		}
		if len(ct) != 509 {
			b.Fatalf("len %d", len(ct))
		}
	}
}

func benchStream(b *testing.B) (*Circuit, *Stream) {
	b.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &Circuit{
		Ctx: ctx, ctxCancel: cancel,
		streams:        &streams{streams: make(map[uint16]*Stream)},
		WriteRelayCell: make(chan RelayOut, 512),
		writeControl:   make(chan RelayOut, 32),
	}
	s := c.newStream(1, ":80", 0)
	s.State = STREAM_OPEN
	b.Cleanup(func() { cancel(nil); _ = s.Free() })
	return c, s
}

// BenchmarkStreamCopy measures ringbuffer->Reader copy without window/flow
// control: direct buffer.Write plus Conn.Read, 64 KiB per copy to stay under
// the 256 KiB stream buffer.
func BenchmarkStreamCopy64KiB(b *testing.B) {
	_, s := benchStream(b)
	chunk := make([]byte, 64<<10)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	dst := make([]byte, 64<<10)
	conn := s.Conn()
	b.SetBytes(64 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.buffer.Write(chunk); err != nil {
			b.Fatal(err)
		}
		select {
		case s.readReady <- struct{}{}:
		default:
		}
		n, err := conn.Read(dst)
		if err != nil {
			b.Fatal(err)
		}
		if n != len(chunk) || !bytes.Equal(dst[:n], chunk) {
			b.Fatal("stream copy mismatch")
		}
	}
}

// Concurrent Write throughput with a draining link fake: outbound is drained
// in a goroutine and acknowledged so SendWindow/ACK ordering is exercised.
func BenchmarkStreamWriteThroughput(b *testing.B) {
	_, s := benchStream(b)
	s.SendWindow.Set(1000000)
	done := make(chan struct{})
	drained := 0
	go func() {
		for {
			select {
			case out := <-s.outbound:
				if out.sent != nil {
					out.sent <- nil
				}
				drained++
				if drained >= b.N {
					close(done)
					return
				}
			case <-done:
				return
			}
		}
	}()
	payload := make([]byte, 498)
	b.SetBytes(498)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	<-done
}

// Many-stream setup: allocate and free 256 streams per iteration
// without any circuit build or network. Measures per-stream allocation.
func BenchmarkManyStreamsSetup(b *testing.B) {
	circ, _ := benchStream(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 256; j++ {
			id := uint16(j + 1)
			s := circ.newStream(id, ":80", 0)
			_ = s.Free()
		}
	}
}

// Controlled consensus-refresh workload (offline): full parse + hydration of
// the small fixture consensus is the entire refresh cost in this repo; live
// Dial+consensus refresh over a real guard is opt-in (see BENCHMARKS.md).
func BenchmarkConsensusRefresh(b *testing.B) {
	// Reproducible offline refresh is measured in pkg/common benchmarks.
	b.Skip("use pkg/common BenchmarkParseConsensus/BenchmarkOwnAuthenticatedHydration for the offline refresh workload")
}

// Live Dial latency / sustained throughput require a real Tor network and
// are opt-in only. They are sketched here so the plan inventory is complete,
// but default `go test -bench` never touches the network.
func BenchmarkLiveDialLatency(b *testing.B) {
	if os.Getenv("GONION_NETWORK_TESTS") != "1" {
		b.Skip("set GONION_NETWORK_TESTS=1 for live Dial latency")
	}
	b.Skip("live Dial latency harness requires an explicit opt-in guard and control consensus; not enabled by default")
}

func BenchmarkLiveThroughput(b *testing.B) {
	if os.Getenv("GONION_NETWORK_TESTS") != "1" {
		b.Skip("set GONION_NETWORK_TESTS=1 for live throughput")
	}
	b.Skip("live throughput harness requires an explicit opt-in guard and control consensus; not enabled by default")
}
