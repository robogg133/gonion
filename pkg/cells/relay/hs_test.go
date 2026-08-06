package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestHSCellsRoundTrip(t *testing.T) {
	auth := ed25519.PublicKey(bytes.Repeat([]byte{0xAA}, 32))

	cases := []Cell{
		&EstIntroCell{
			AuthKey: auth,
			Exts:    []Ext{{Type: 1, Data: []byte{1, 2, 3}}},
			MAC:     bytes.Repeat([]byte{0x11}, 32),
			Sig:     bytes.Repeat([]byte{0x22}, 64),
		},
		&EstRendezvousCell{Cookie: [20]byte{1, 2, 3}},
		&Introduce1Cell{
			introHead: introHead{
				AuthKey: auth,
				Exts:    []Ext{{Type: 2, Data: []byte{9}}},
			},
			Encrypted: bytes.Repeat([]byte{0x77}, 246),
		},
		&Introduce2Cell{
			introHead: introHead{AuthKey: auth},
			Payload:   []byte{0xDE, 0xAD},
		},
		&Rendezvous1Cell{
			Cookie:        [20]byte{4, 5, 6},
			HandshakeInfo: bytes.Repeat([]byte{0x33}, 64),
		},
		&Rendezvous2Cell{HandshakeInfo: bytes.Repeat([]byte{0x44}, 64)},
		&IntroEstablishedCell{Exts: []Ext{{Type: 3, Data: []byte{0x01}}}},
		&RendezvousEstablishedCell{},
		&IntroduceAckCell{Status: INTRO_ACK_SUCCESS, Exts: []Ext{{Type: 1, Data: []byte{7}}}},
	}

	for _, c := range cases {
		var buf bytes.Buffer
		if err := c.Encode(&buf); err != nil {
			t.Fatalf("encode %T: %v", c, err)
		}
		f := AllKnownRellayCells[c.ID()]
		if f == nil {
			t.Fatalf("%T: command %d not registered", c, c.ID())
		}
		dec := f()
		dec.SetStreamID(0)
		if err := dec.Decode(bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("decode %T: %v", c, err)
		}
		if !reflect.DeepEqual(c, dec) {
			t.Fatalf("%T round-trip mismatch:\n got %#v\n want %#v", c, dec, c)
		}
	}
}

func TestHSWireBytes(t *testing.T) {
	auth := ed25519.PublicKey(bytes.Repeat([]byte{0xAA}, 32))

	// ESTABLISH_INTRO: AUTH_KEY_TYPE=2, len=32, key, N_EXTENSIONS=1, ext,
	// MAC, SIG_LEN=64, sig.
	var intro bytes.Buffer
	cell := &EstIntroCell{
		AuthKey: auth,
		Exts:    []Ext{{Type: 0x42, Data: []byte{0xAB}}},
		MAC:     bytes.Repeat([]byte{0x11}, 32),
		Sig:     bytes.Repeat([]byte{0x22}, 64),
	}
	if err := cell.Encode(&intro); err != nil {
		t.Fatal(err)
	}
	want := 1 + 2 + 32 + 1 + 1 + 1 + 1 + 32 + 2 + 64
	if intro.Len() != want {
		t.Fatalf("EST_INTRO len = %d, want %d", intro.Len(), want)
	}
	b := intro.Bytes()
	if b[0] != 2 || binary.BigEndian.Uint16(b[1:3]) != 32 {
		t.Fatalf("EST_INTRO head wrong: %x", b[:3])
	}

	// INTRO_ACK: STATUS is u16, status bytes precede N_EXTENSIONS.
	var ack bytes.Buffer
	if err := (&IntroduceAckCell{Status: INTRO_ACK_BAD_FORMAT}).Encode(&ack); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ack.Bytes(), []byte{0x00, 0x02, 0x00}) {
		t.Fatalf("INTRO_ACK bytes = %x", ack.Bytes())
	}

	// RendezvousEstablished is an empty body and ignores trailing junk.
	var rdv bytes.Buffer
	if err := (&RendezvousEstablishedCell{}).Encode(&rdv); err != nil {
		t.Fatal(err)
	}
	if rdv.Len() != 0 {
		t.Fatalf("RENDEZVOUS_ESTABLISHED len = %d, want 0", rdv.Len())
	}
	rd := &RendezvousEstablishedCell{}
	_ = rd.Decode(bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04}))

	// IntroEstablished: empty legacy body and extension-bearing body both parse.
	ie := &IntroEstablishedCell{}
	if err := ie.Decode(bytes.NewReader(nil)); err != nil {
		t.Fatalf("legacy empty INTRO_ESTABLISHED: %v", err)
	}
	var ieBuf bytes.Buffer
	if err := (&IntroEstablishedCell{Exts: []Ext{{Type: 1, Data: []byte{0xAA}}}}).Encode(&ieBuf); err != nil {
		t.Fatal(err)
	}
	if err := ie.Decode(bytes.NewReader(ieBuf.Bytes())); err != nil {
		t.Fatalf("INTRO_ESTABLISHED with ext: %v", err)
	}
}
