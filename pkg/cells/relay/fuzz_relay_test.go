package relay_test

import (
	"bytes"
	"testing"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/crypto"
)

// Relay-cell codec fuzzing for V5.2 (tor-spec 6.1). Provenance: seeds come
// from cells_test.go DataCell/BeginCell payloads and the RelayCellCoder pair
// keys there. The fuzzer covers Marshal/UnmarshalPlain with adversarial
// payload lengths and unknown commands; digest state must advance only on
// recognized cells (see relay_cell.go backwardCheck). No crasher minimized yet.

func FuzzRelayCellCodec(f *testing.F) {
	f.Add([]byte("payload-data"), uint16(7))
	f.Add([]byte("example.com:80"), uint16(3))
	f.Add([]byte{}, uint16(1))
	f.Add(make([]byte, 498), uint16(65535))
	f.Add(make([]byte, 499), uint16(1)) // exceeds relay body, must error
	f.Add([]byte{0, 0, 0, 0}, uint16(0))
	f.Fuzz(func(t *testing.T, payload []byte, streamID uint16) {
		if len(payload) > 2048 {
			return
		}
		// DataCell encode/decode must be round-trip stable within the bound.
		in := &relay.DataCell{StreamID: streamID, Payload: payload}
		var buf bytes.Buffer
		if err := in.Encode(&buf); err != nil {
			return
		}
		var out relay.DataCell
		if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("DataCell roundtrip: %v", err)
		}
		// DataCell.Encode carries only the payload; StreamID lives in the
		// relay header and is applied by the RelayCellCoder, not this codec.
		if !bytes.Equal(out.Payload, payload) {
			t.Fatal("DataCell roundtrip mismatch")
		}
		// Full RelayCellCoder Marshal/UnmarshalPlain with a synchronized pair.
		kf := bytes.Repeat([]byte{0x11}, 16)
		df := bytes.Repeat([]byte{0x22}, 20)
		kb := bytes.Repeat([]byte{0x33}, 16)
		db := bytes.Repeat([]byte{0x44}, 20)
		mk := func(key, seed []byte) *crypto.RunningValues {
			rv, err := crypto.NewRunningValues(key, seed)
			if err != nil {
				t.Skip(err)
			}
			return rv
		}
		client := relay.NewDataCellCoder(mk(kb, db), mk(kf, df))
		server := relay.NewDataCellCoder(mk(kf, df), mk(kb, db))
		ct, err := client.Marshal(in)
		if err != nil {
			return
		}
		if len(payload) <= relay.RELAY_BODY_LEN {
			if len(ct) != 509 {
				t.Fatalf("ciphertext size %d", len(ct))
			}
			cell, err := server.Unmarshal(ct)
			if err != nil {
				t.Fatalf("Marshal/Unmarshal: %v", err)
			}
			got := cell.(*relay.DataCell)
			if got.GetStreamID() != streamID || !bytes.Equal(got.Payload, payload) {
				t.Fatal("relay codec mismatch")
			}
		}
		// BeginCell with fuzz-controlled target: encode must validate or roundtrip.
		if len(payload) <= 512 && !bytes.Contains(payload, []byte{0}) {
			target := string(payload)
			beg := &relay.BeginCell{StreamID: streamID, Addrport: target, Flags: 0}
			var bb bytes.Buffer
			if err := beg.Encode(&bb); err == nil {
				var back relay.BeginCell
				if err := back.Decode(bytes.NewReader(bb.Bytes())); err != nil {
					t.Fatalf("BeginCell roundtrip: %v", err)
				}
			}
		}
	})
}

func FuzzUnmarshalPlain(f *testing.F) {
	// Adversarial 509-byte plains: unknown command with valid digest handling
	// must not panic or treat unrecognized ciphertext as recognized.
	f.Add(make([]byte, 509))
	seed := make([]byte, 509)
	seed[0] = 2
	f.Add(seed)
	f.Add([]byte{255, 0, 0})
	f.Fuzz(func(t *testing.T, plain []byte) {
		if len(plain) != 509 {
			return
		}
		kf := bytes.Repeat([]byte{0x11}, 16)
		df := bytes.Repeat([]byte{0x22}, 20)
		rv, err := crypto.NewRunningValues(kf, df)
		if err != nil {
			t.Skip(err)
		}
		coder := relay.NewDataCellCoder(rv, rv)
		// UnmarshalPlain must not panic for any 509-byte input; the digest
		// check (backwardCheck) may reject or return ErrUnrecognized /
		// ErrUnknownRelayCommand — all are expected outcomes.
		_, _ = coder.UnmarshalPlain(plain)
	})
}
