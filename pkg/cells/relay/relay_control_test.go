package relay_test

// Parser-side C1.3/C1.4 coverage, derived from tor-spec.txt:
//   - 6.1: "If the RELAY cell is recognized but the relay command is not
//     understood, the cell must be dropped and ignored. Its contents still
//     count with respect to the digests and flow control windows, though."
//   - 6.1: commands 9 RELAY_TRUNCATED / 10 RELAY_DROP; 5.4: the payload of
//     a RELAY_TRUNCATED cell contains a single octet describing the reason.
//   - 6.2: "Relay RELAY_DROP cells are long-range dummies; upon receiving
//     such a cell, the OR or OP must drop it."
//   - 6.3: "Implementations SHOULD accept empty RELAY_END messages, and
//     treat them as if they specified REASON_MISC"; "OPs and ORs MUST
//     accept reasons not on the above list".

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/crypto"
)

// unknownCell is a test-only Cell carrying a command byte the relay
// package does not register, so Marshal produces a cell with a valid
// running digest for the receiving hop.
type unknownCell struct {
	streamID uint16
	id       uint8
}

func (c *unknownCell) ID() uint8              { return c.id }
func (c *unknownCell) GetStreamID() uint16    { return c.streamID }
func (c *unknownCell) SetStreamID(n uint16)   { c.streamID = n }
func (c *unknownCell) Encode(io.Writer) error { return nil }
func (c *unknownCell) Decode(io.Reader) error { return nil }

func coderPair(t *testing.T) (client, server *relay.RelayCellCoder) {
	t.Helper()
	kf := bytes.Repeat([]byte{0x11}, 16)
	df := bytes.Repeat([]byte{0x22}, 20)
	kb := bytes.Repeat([]byte{0x33}, 16)
	db := bytes.Repeat([]byte{0x44}, 20)
	mk := func(key, seed []byte) *crypto.RunningValues {
		rv, err := crypto.NewRunningValues(key, seed)
		if err != nil {
			t.Fatal(err)
		}
		return rv
	}
	client = relay.NewDataCellCoder(mk(kb, db), mk(kf, df))
	server = relay.NewDataCellCoder(mk(kf, df), mk(kb, db))
	return client, server
}

// sealPlain returns a copy of plain with the running digest a hop seeded
// with kf/df would compute over it (digest field zeroed), so UnmarshalPlain
// on a fresh coder with the same backwards values recognizes it.
func sealPlain(t *testing.T, kf, seed []byte, plain []byte) []byte {
	t.Helper()
	out := append([]byte(nil), plain...)
	clear(out[5:9])
	rv, err := crypto.NewRunningValues(kf, seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := rv.Write(out); err != nil {
		t.Fatal(err)
	}
	copy(out[5:9], rv.Sum()[:4])
	return out
}

func freshCoder(t *testing.T) *relay.RelayCellCoder {
	t.Helper()
	kf := bytes.Repeat([]byte{1}, 16)
	df := bytes.Repeat([]byte{2}, 20)
	rv, err := crypto.NewRunningValues(kf, df)
	if err != nil {
		t.Fatal(err)
	}
	fwd, err := crypto.NewRunningValues(kf, df)
	if err != nil {
		t.Fatal(err)
	}
	return relay.NewDataCellCoder(rv, fwd)
}

func TestUnknownCommand_Recognized_SentinelAndDigestAdvances(t *testing.T) {
	client, server := coderPair(t)

	ct, err := client.Marshal(&unknownCell{streamID: 0, id: 0xfe})
	if err != nil {
		t.Fatal(err)
	}
	cell, err := server.Unmarshal(ct)
	if cell != nil {
		t.Fatalf("expected nil cell, got %T", cell)
	}
	if !errors.Is(err, relay.ErrUnknownRelayCommand) {
		t.Fatalf("expected ErrUnknownRelayCommand, got %v", err)
	}
	if errors.Is(err, relay.ErrUnrecognized) {
		t.Fatalf("recognized unknown command must not match ErrUnrecognized: %v", err)
	}

	// Digest must have advanced (and the keystream stayed in sync): the
	// next cell on the same hop still validates.
	payload := []byte("after-unknown")
	ct, err = client.Marshal(&relay.DataCell{StreamID: 5, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	cell, err = server.Unmarshal(ct)
	if err != nil {
		t.Fatalf("cell after unknown command should validate: %v", err)
	}
	if got := cell.(*relay.DataCell); got.GetStreamID() != 5 || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("got sid=%d payload=%q", got.GetStreamID(), got.Payload)
	}
}

func TestUnknownCommand_UnmarshalPlain_Sealed(t *testing.T) {
	kf := bytes.Repeat([]byte{1}, 16)
	df := bytes.Repeat([]byte{2}, 20)
	plain := make([]byte, 509)
	plain[0] = 0xfe
	// StreamID 42 at [3:5], payload length 0 at [9:11].
	plain[3], plain[4] = 0, 42
	sealed := sealPlain(t, kf, df, plain)

	_, err := freshCoder(t).UnmarshalPlain(sealed)
	if !errors.Is(err, relay.ErrUnknownRelayCommand) {
		t.Fatalf("expected ErrUnknownRelayCommand, got %v", err)
	}
}

func TestUnmarshalPlain_Bounds(t *testing.T) {
	// Short inputs must error, not panic, and not be misreported as a
	// recognized unknown command.
	for _, plain := range [][]byte{nil, make([]byte, 8), make([]byte, 508)} {
		_, err := freshCoder(t).UnmarshalPlain(plain)
		if err == nil {
			t.Fatal("expected length error")
		}
		if errors.Is(err, relay.ErrUnknownRelayCommand) {
			t.Fatalf("short input must not match sentinel: %v", err)
		}
	}

	// Payload length beyond the 498-byte relay body, with a valid digest
	// so the bounds check (not the digest check) is what fails.
	kf := bytes.Repeat([]byte{1}, 16)
	df := bytes.Repeat([]byte{2}, 20)
	plain := make([]byte, 509)
	plain[0] = relay.COMMAND_DATA
	plain[9], plain[10] = 1, 243 // 499
	_, err := freshCoder(t).UnmarshalPlain(sealPlain(t, kf, df, plain))
	if err == nil || errors.Is(err, relay.ErrUnknownRelayCommand) || errors.Is(err, relay.ErrUnrecognized) {
		t.Fatalf("expected payload-length error, got %v", err)
	}
}

func TestRelayDrop_Ignorable(t *testing.T) {
	for _, id := range []uint8{relay.COMMAND_RELAY_DROP, relay.COMMAND_RELAY_TRUNCATED} {
		if _, ok := relay.AllKnownRellayCells[id]; !ok {
			t.Fatalf("command %d not registered", id)
		}
	}
	if relay.COMMAND_RELAY_DROP != 10 {
		t.Fatalf("RELAY_DROP=%d, want 10 (tor-spec 6.1)", relay.COMMAND_RELAY_DROP)
	}
	if relay.COMMAND_RELAY_TRUNCATED != 9 {
		t.Fatalf("RELAY_TRUNCATED=%d, want 9 (tor-spec 6.1)", relay.COMMAND_RELAY_TRUNCATED)
	}

	in := &relay.RelayDropCell{StreamID: 0}
	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("DROP must have empty payload, got %d bytes", buf.Len())
	}
	out := &relay.RelayDropCell{}
	// Any payload bytes are ignored: DROP is a dummy.
	if err := out.Decode(bytes.NewReader([]byte("ignored"))); err != nil {
		t.Fatal(err)
	}

	client, server := coderPair(t)
	ct, err := client.Marshal(&relay.RelayDropCell{StreamID: 0})
	if err != nil {
		t.Fatal(err)
	}
	cell, err := server.Unmarshal(ct)
	if err != nil {
		t.Fatalf("DROP should decode without error: %v", err)
	}
	if cell.ID() != relay.COMMAND_RELAY_DROP || cell.GetStreamID() != 0 {
		t.Fatalf("got id=%d sid=%d", cell.ID(), cell.GetStreamID())
	}
}

func TestRelayTruncated_RoundTrip(t *testing.T) {
	in := &relay.RelayTruncatedCell{StreamID: 0, Reason: relay.TRUNCATED_REASON_DESTROYED}
	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 1 || buf.Bytes()[0] != relay.TRUNCATED_REASON_DESTROYED {
		t.Fatalf("TRUNCATED payload=%v, want single reason octet", buf.Bytes())
	}
	out := &relay.RelayTruncatedCell{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if out.Reason != relay.TRUNCATED_REASON_DESTROYED {
		t.Fatalf("reason=%d", out.Reason)
	}

	// Unknown reason values are accepted, mirroring RELAY_END handling.
	var unk relay.RelayTruncatedCell
	if err := unk.Decode(bytes.NewReader([]byte{0xff})); err != nil || unk.Reason != 0xff {
		t.Fatalf("unknown truncated reason: %+v, %v", unk, err)
	}
	// Empty payload is not a decodable TRUNCATED cell (unlike RELAY_END).
	if err := new(relay.RelayTruncatedCell).Decode(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected error for empty TRUNCATED payload")
	}

	client, server := coderPair(t)
	ct, err := client.Marshal(&relay.RelayTruncatedCell{StreamID: 0, Reason: relay.TRUNCATED_REASON_TIMEOUT})
	if err != nil {
		t.Fatal(err)
	}
	cell, err := server.Unmarshal(ct)
	if err != nil {
		t.Fatal(err)
	}
	got := cell.(*relay.RelayTruncatedCell)
	if got.GetStreamID() != 0 || got.Reason != relay.TRUNCATED_REASON_TIMEOUT {
		t.Fatalf("got %+v", got)
	}
}

func TestRelayEnd_EmptyIsMisc_UnknownAccepted(t *testing.T) {
	var empty relay.RelayEndCell
	if err := empty.Decode(bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if empty.Reason != relay.END_REASON_MISC {
		t.Fatalf("empty RELAY_END reason=%d, want MISC=%d", empty.Reason, relay.END_REASON_MISC)
	}

	var unk relay.RelayEndCell
	if err := unk.Decode(bytes.NewReader([]byte{99})); err != nil || unk.Reason != 99 {
		t.Fatalf("unknown RELAY_END reason must be accepted: %+v, %v", unk, err)
	}

	// REASON_EXITPOLICY carries extra address/TTL bytes; the reason byte
	// is still decoded and extra bytes do not fail parsing.
	var exit relay.RelayEndCell
	body := []byte{relay.END_REASON_EXITPOLICY, 192, 0, 2, 1, 0, 0, 0, 5}
	if err := exit.Decode(bytes.NewReader(body)); err != nil || exit.Reason != relay.END_REASON_EXITPOLICY {
		t.Fatalf("EXITPOLICY RELAY_END: %+v, %v", exit, err)
	}

	client, server := coderPair(t)
	ct, err := client.Marshal(&relay.RelayEndCell{StreamID: 9, Reason: relay.END_REASON_DONE})
	if err != nil {
		t.Fatal(err)
	}
	cell, err := server.Unmarshal(ct)
	if err != nil {
		t.Fatal(err)
	}
	if got := cell.(*relay.RelayEndCell); got.GetStreamID() != 9 || got.Reason != relay.END_REASON_DONE {
		t.Fatalf("got %+v", got)
	}
}
