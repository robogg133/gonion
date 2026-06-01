package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/handshakes"
)

var (
	addr           = "81.169.159.28:29001"
	nodeID         = [20]byte{255, 250, 145, 241, 134, 99, 248, 204, 232, 231, 37, 162, 73, 63, 133, 179, 144, 184, 211, 55}
	ntor_onion_key = []byte{141, 117, 229, 70, 174, 197, 90, 84, 190, 96, 10, 68, 17, 55, 60, 254, 63, 82, 16, 212, 91, 175, 217, 117, 130, 178, 95, 39, 133, 12, 182, 23}
)

func TestCreate2Circuit(t *testing.T) {

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	conn, err := gonion.NewConn(c)
	if err != nil {
		t.Fatal(err)
	}

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ntorHs := &handshakes.Client_NTorHandshake{
		NodeID:    nodeID,
		KeyID:     ntor_onion_key,
		PublicKey: pk,
	}

	_, err = conn.NewCircuit(1, handshakes.HTYPE_NTOR, ntorHs, pk, sk)
	if err != nil {
		t.Fatal(err)
	}

}
