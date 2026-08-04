package relay

import (
	"bytes"
	"crypto/ed25519"
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