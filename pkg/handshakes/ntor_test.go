package handshakes_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/robogg133/gonion/pkg/handshakes"
)

func TestClientNTor_EncodeDecode(t *testing.T) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	onionSK, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var nodeID [20]byte
	copy(nodeID[:], bytes.Repeat([]byte{0x7a}, 20))

	in := &handshakes.Client_NTorHandshake{
		NodeID:     nodeID,
		KeyID:      onionSK.PublicKey(),
		PrivateKey: sk,
		PublicKey:  sk.PublicKey(),
	}

	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	// 20 node + 32 onion + 32 client pk
	if buf.Len() != 84 {
		t.Fatalf("len=%d want 84", buf.Len())
	}

	out := &handshakes.Client_NTorHandshake{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if out.NodeID != nodeID {
		t.Fatal("node id")
	}
	if !bytes.Equal(out.KeyID.Bytes(), onionSK.PublicKey().Bytes()) {
		t.Fatal("key id")
	}
	if !bytes.Equal(out.PublicKey.Bytes(), sk.PublicKey().Bytes()) {
		t.Fatal("public key")
	}
}

func TestServerNTor_EncodeDecode(t *testing.T) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := bytes.Repeat([]byte{0x5c}, 32)
	in := &handshakes.Server_NTorHandshake{
		PublicKey: sk.PublicKey(),
		Auth:      auth,
	}

	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 64 {
		t.Fatalf("len=%d", buf.Len())
	}

	out := &handshakes.Server_NTorHandshake{}
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.PublicKey.Bytes(), sk.PublicKey().Bytes()) {
		t.Fatal("pk")
	}
	if !bytes.Equal(out.Auth, auth) {
		t.Fatal("auth")
	}
}

func TestServerNTor_EncodeRejectsBadAuth(t *testing.T) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	in := &handshakes.Server_NTorHandshake{
		PublicKey: sk.PublicKey(),
		Auth:      []byte{1, 2, 3},
	}
	if err := in.Encode(&bytes.Buffer{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestHTYPE_NTOR(t *testing.T) {
	if handshakes.HTYPE_NTOR != 0x0002 {
		t.Fatalf("%d", handshakes.HTYPE_NTOR)
	}
}
