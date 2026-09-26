package hs

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/desc"
)

// Unimplemented methods panic through the embedded nil interface. In
// particular, opening a stream during introduction must fail this test.
type introControlCircuit struct {
	capi.Circ
	sent []relay.Cell
	ack  relay.Cell
	err  error
}

func (c *introControlCircuit) SendHSControl(cell relay.Cell) error {
	c.sent = append(c.sent, cell)
	return nil
}

func (c *introControlCircuit) RecvHSControl(context.Context) (relay.Cell, error) {
	return c.ack, c.err
}

func TestIntroductionUsesCircuitControl(t *testing.T) {
	// Authentication key from rend-spec-v3 Appendix G.1. Encryption is tested
	// against the complete official capture in crypto/hs_ntor_vector_test.go.
	auth, err := hex.DecodeString("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ack  relay.Cell
		err  error
		ok   bool
	}{
		{"success", &relay.IntroduceAckCell{Status: relay.INTRO_ACK_SUCCESS}, nil, true},
		{"rejected", &relay.IntroduceAckCell{Status: 1}, nil, false},
		{"wrong command", &relay.IntroEstablishedCell{}, nil, false},
		{"closed channel", nil, nil, false},
		{"cancelled", nil, context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			circ := &introControlCircuit{ack: tc.ack, err: tc.err}
			err := sendIntroduction(context.Background(), circ, auth, []byte("opaque encrypted payload"))
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected result: %v", err)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("lost receive error: %v", err)
			}
			if len(circ.sent) != 1 || circ.sent[0].ID() != relay.COMMAND_INTRODUCE1 || circ.sent[0].GetStreamID() != 0 {
				t.Fatalf("expected exactly one INTRODUCE1 control cell: %v", circ.sent)
			}
		})
	}
}

func TestFinishRendezvousUsesSelectedIntroKey(t *testing.T) {
	// Fixed values from rend-spec-v3 Appendix G.1, captured from Tor/Chutney.
	decode := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	x, err := ecdh.X25519().NewPrivateKey(decode("60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341"))
	if err != nil {
		t.Fatal(err)
	}
	B, err := ecdh.X25519().NewPublicKey(decode("8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979"))
	if err != nil {
		t.Fatal(err)
	}
	auth := decode("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	client := &Client{introPrivX: x, introB: B, introAuth: auth}
	d := &desc.Descriptor{IntroPoints: []desc.IntroPoint{
		{AuthKey: bytes.Repeat([]byte{1}, 32)},
		{AuthKey: auth},
	}}
	reply := decode("8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE7004A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208")
	seed, err := client.finishRendezvous(d, reply)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed, decode("4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB")) {
		t.Fatal("wrong seed for selected introduction point")
	}
	if _, err := (&Client{}).finishRendezvous(nil, reply); err == nil {
		t.Fatal("accepted missing handshake state")
	}
}
