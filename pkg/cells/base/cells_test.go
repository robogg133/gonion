package cells_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	cells "github.com/robogg133/gonion/pkg/cells/base"
)

func TestCellCoder_CreateFast_RoundTrip(t *testing.T) {
	coder := cells.NewCellCoder(cells.AllKnownCells)
	var x [20]byte
	for i := range x {
		x[i] = byte(i + 1)
	}
	in := &cells.CreateFastCell{CircuitID: 0x80000001, X: x}

	raw, err := coder.MarshalCell(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4+1+cells.CELL_BODY_LEN {
		t.Fatalf("len=%d", len(raw))
	}
	if binary.BigEndian.Uint32(raw[:4]) != 0x80000001 {
		t.Fatal("circuit id")
	}
	if raw[4] != cells.COMMAND_CREATE_FAST {
		t.Fatal("command")
	}

	got, err := coder.ReadCell(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	out := got.(*cells.CreateFastCell)
	if out.X != x {
		t.Fatalf("X mismatch: %x", out.X)
	}
}

func TestCellCoder_Destroy_RoundTrip(t *testing.T) {
	coder := cells.NewCellCoder(cells.AllKnownCells)
	in := &cells.DestroyCell{CircuitID: 0x80000002, Reason: cells.DESTROY_REASON_TIMEOUT}

	raw, err := coder.MarshalCell(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := coder.ReadCell(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	out := got.(*cells.DestroyCell)
	if out.Reason != cells.DESTROY_REASON_TIMEOUT {
		t.Fatalf("reason=%d", out.Reason)
	}
}

func TestCellCoder_UnknownCommand(t *testing.T) {
	coder := cells.NewCellCoder(cells.AllKnownCells)
	raw := make([]byte, 4+1+cells.CELL_BODY_LEN)
	raw[4] = 0xff // unknown
	_, err := coder.ReadCell(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRelayCell_OpaqueBody(t *testing.T) {
	body := make([]byte, cells.CELL_BODY_LEN)
	for i := range body {
		body[i] = byte(i)
	}
	cell := &cells.RelayCell{CircuitID: 0x80000001, Body: body}

	var buf bytes.Buffer
	if err := cell.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != cells.CELL_BODY_LEN {
		t.Fatalf("encode len = %d", buf.Len())
	}

	out := &cells.RelayCell{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Body, body) {
		t.Fatal("body mismatch")
	}
}

func TestRelayCell_EncodePadsShortBody(t *testing.T) {
	cell := &cells.RelayCell{Body: []byte{1, 2, 3}}
	var buf bytes.Buffer
	if err := cell.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != cells.CELL_BODY_LEN {
		t.Fatalf("len = %d", buf.Len())
	}
	if buf.Bytes()[0] != 1 || buf.Bytes()[2] != 3 {
		t.Fatal("prefix not preserved")
	}
}

func TestRelayEarlyCell_DelegatesBody(t *testing.T) {
	body := bytes.Repeat([]byte{0x7e}, cells.CELL_BODY_LEN)
	early := &cells.RelayEarlyCell{C: &cells.RelayCell{CircuitID: 9, Body: body}}

	if early.ID() != cells.COMMAND_RELAY_EARLY {
		t.Fatal("id")
	}
	if early.GetCircuitID() != 9 {
		t.Fatal("circ id")
	}

	var buf bytes.Buffer
	if err := early.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	out := &cells.RelayEarlyCell{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.C.Body, body) {
		t.Fatal("body")
	}
}

func TestCellCoder_RelayRoundTrip(t *testing.T) {
	coder := cells.NewCellCoder(cells.AllKnownCells)
	body := bytes.Repeat([]byte{0xab}, cells.CELL_BODY_LEN)
	raw, err := coder.MarshalCell(&cells.RelayCell{
		CircuitID: 0x80000002,
		Body:      body,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := coder.ReadCell(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	rc := got.(*cells.RelayCell)
	if !bytes.Equal(rc.Body, body) {
		t.Fatal("body mismatch")
	}
}

func TestCreatedFast_Decode(t *testing.T) {
	// CREATED_FAST Encode is currently a no-op; test Decode against a hand-built body.
	coder := cells.NewCellCoder(cells.AllKnownCells)
	var y, kh [20]byte
	copy(y[:], bytes.Repeat([]byte{0xaa}, 20))
	copy(kh[:], bytes.Repeat([]byte{0xbb}, 20))

	raw := make([]byte, 4+1+cells.CELL_BODY_LEN)
	binary.BigEndian.PutUint32(raw[0:4], 0x80000003)
	raw[4] = cells.COMMAND_CREATED_FAST
	copy(raw[5:25], y[:])
	copy(raw[25:45], kh[:])

	got, err := coder.ReadCell(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	out := got.(*cells.CreatedFastCell)
	if out.Y != y || out.KH != kh {
		t.Fatal("fields")
	}
}
