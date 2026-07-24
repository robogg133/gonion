package relay_test

import (
	"bytes"
	"testing"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/crypto"
)

func TestIsDecrypted(t *testing.T) {
	body := make([]byte, 11)
	if relay.IsDecrypted(body) {
		// recognized at [1:3] is already 0,0 — true for zero body
	}
	body[1], body[2] = 1, 2
	if relay.IsDecrypted(body) {
		t.Fatal("should not be decrypted when recognized != 0")
	}
	body[1], body[2] = 0, 0
	if !relay.IsDecrypted(body) {
		t.Fatal("recognized zero should count as decrypted candidate")
	}
}

func TestDataCell_EncodeDecode(t *testing.T) {
	in := &relay.DataCell{StreamID: 7, Payload: []byte("payload-data")}
	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	out := &relay.DataCell{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("got %q", out.Payload)
	}
}

func TestBeginCell_EncodeDecode(t *testing.T) {
	in := &relay.BeginCell{StreamID: 3, Addrport: "example.com:80"}
	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Bytes()[buf.Len()-1] != 0 {
		t.Fatal("missing NUL terminator")
	}
	out := &relay.BeginCell{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	// ReadString includes the delimiter.
	if out.Addrport != "example.com:80\x00" {
		t.Fatalf("addrport=%q", out.Addrport)
	}
}

func TestBeginDir_Connected_EmptyPayload(t *testing.T) {
	for _, cell := range []relay.Cell{
		&relay.BeginDirCell{StreamID: 1},
		&relay.ConnectedCell{StreamID: 1},
	} {
		var buf bytes.Buffer
		if err := cell.Encode(&buf); err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Fatalf("%T encoded non-empty body", cell)
		}
	}
}

func TestSendMe_V1_RoundTrip(t *testing.T) {
	in := &relay.SendMeCell{
		StreamID:        0,
		Version:         1,
		Sha1ForLastCell: [20]byte{1, 2, 3, 4, 5},
	}
	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	out := &relay.SendMeCell{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if out.Version != 1 || out.Sha1ForLastCell != in.Sha1ForLastCell {
		t.Fatalf("got %+v", out)
	}
}

func TestSendMe_V0_RoundTrip(t *testing.T) {
	in := &relay.SendMeCell{StreamID: 0, Version: 0}
	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	out := &relay.SendMeCell{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if out.Version != 0 {
		t.Fatalf("version=%d", out.Version)
	}
}

func TestRelayEnd_RoundTrip(t *testing.T) {
	in := &relay.RelayEndCell{StreamID: 9, Reason: relay.END_REASON_MISC}
	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	out := &relay.RelayEndCell{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if out.Reason != relay.END_REASON_MISC {
		t.Fatalf("reason=%d", out.Reason)
	}
}

func TestRelayCellCoder_MarshalUnmarshal_Data(t *testing.T) {
	kf := bytes.Repeat([]byte{0x11}, 16)
	df := bytes.Repeat([]byte{0x22}, 20)
	kb := bytes.Repeat([]byte{0x33}, 16)
	db := bytes.Repeat([]byte{0x44}, 20)

	// Client-side coder
	fwd, err := crypto.NewRunningValues(kf, df)
	if err != nil {
		t.Fatal(err)
	}
	bwd, err := crypto.NewRunningValues(kb, db)
	if err != nil {
		t.Fatal(err)
	}
	client := relay.NewDataCellCoder(bwd, fwd)

	// Server peels with client forward keys as its backward
	sfwd, err := crypto.NewRunningValues(kb, db)
	if err != nil {
		t.Fatal(err)
	}
	sbwd, err := crypto.NewRunningValues(kf, df)
	if err != nil {
		t.Fatal(err)
	}
	server := relay.NewDataCellCoder(sbwd, sfwd)

	payload := []byte("unit-test-payload")
	ct, err := client.Marshal(&relay.DataCell{StreamID: 5, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 509 {
		t.Fatalf("len=%d", len(ct))
	}

	cell, err := server.Unmarshal(append([]byte(nil), ct...))
	if err != nil {
		t.Fatal(err)
	}
	got := cell.(*relay.DataCell)
	if got.GetStreamID() != 5 || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("got sid=%d payload=%q", got.GetStreamID(), got.Payload)
	}
}

func TestRelayCellCoder_UnknownCommand(t *testing.T) {
	kf := bytes.Repeat([]byte{1}, 16)
	df := bytes.Repeat([]byte{2}, 20)
	fwd, _ := crypto.NewRunningValues(kf, df)
	bwd, _ := crypto.NewRunningValues(kf, df)
	coder := relay.NewDataCellCoder(bwd, fwd)

	// Build a fake decrypted body with unknown cmd 0xfe and recognized=0
	plain := make([]byte, 509)
	plain[0] = 0xfe
	// recognized already 0
	_, err := coder.UnmarshalPlain(plain)
	if err == nil {
		t.Fatal("expected unknown command error")
	}
}

func TestAllKnownRelayCells_Registered(t *testing.T) {
	need := []uint8{
		relay.COMMAND_BEGIN,
		relay.COMMAND_DATA,
		relay.COMMAND_CONNECTED,
		relay.COMMAND_SENDME,
		relay.COMMAND_RELAY_END,
		relay.COMMAND_BEGIN_DIR,
		relay.COMMAND_EXTEND2,
		relay.COMMAND_EXTENDED2,
	}
	for _, id := range need {
		if _, ok := relay.AllKnownRellayCells[id]; !ok {
			t.Fatalf("command %d not registered", id)
		}
	}
}
