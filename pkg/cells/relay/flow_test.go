package relay

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSendmeWireBoundaries(t *testing.T) {
	// tor-spec 7.3.1/7.4 define empty v0 and stream cells and at least
	// 20 digest bytes for v1. Truncated digests must return errors, not panic.
	for n := 0; n < 20; n++ {
		raw := []byte{1, 0, byte(n)}
		raw = append(raw, make([]byte, n)...)
		if err := (&SendMeCell{}).Decode(bytes.NewReader(raw)); err == nil {
			t.Fatalf("accepted digest length %d", n)
		}
	}
	for _, raw := range [][]byte{{1}, {1, 0}, {1, 0, 20}, {2, 0, 20}, {1, 255, 255}} {
		if err := (&SendMeCell{}).Decode(bytes.NewReader(raw)); err == nil {
			t.Fatalf("accepted %x", raw)
		}
	}
	for _, raw := range [][]byte{nil, {0}, {0, 255, 255}} {
		if err := (&SendMeCell{}).Decode(bytes.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := (&SendMeCell{StreamID: 1, Version: 1}).Encode(&out); err != nil || out.Len() != 0 {
		t.Fatal("stream SENDME must be empty")
	}
	var stream SendMeCell
	stream.StreamID = 1
	if err := stream.Decode(bytes.NewReader([]byte{255})); err != nil {
		t.Fatal("stream body was not ignored")
	}
	raw := append([]byte{1, 0, 21}, bytes.Repeat([]byte{3}, 21)...)
	var cell SendMeCell
	if err := cell.Decode(bytes.NewReader(raw)); err != nil || cell.Sha1ForLastCell != [20]byte(bytes.Repeat([]byte{3}, 20)) {
		t.Fatal("extended digest not accepted")
	}
}

func TestBeginWireBounds(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(":80"), []byte(":0\x00"), []byte(":65536\x00"), []byte("bad\x00"), bytes.Repeat([]byte{'a'}, 499)} {
		if err := (&BeginCell{}).Decode(bytes.NewReader(raw)); err == nil {
			t.Fatalf("accepted BEGIN %q", raw)
		}
	}
	raw := append([]byte(":80\x00"), binary.BigEndian.AppendUint32(nil, 0x80000000)...)
	if err := (&BeginCell{}).Decode(bytes.NewReader(raw)); err != nil {
		t.Fatalf("reserved receive flags: %v", err)
	}
}
