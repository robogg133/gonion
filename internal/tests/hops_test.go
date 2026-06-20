package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"

	"github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/handshakes"
	"github.com/robogg133/gonion/pkg/lspec"
	"github.com/robogg133/gonion/pkg/path"
)

func TestConnect(t *testing.T) {

	dialer := fallback.New(shared.Fallbacks)

	c, err := dialer.Dial(true)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Using addr %s from fallback dirs\n", c.RemoteAddr().String())

	conn, err := gonion.NewConn(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created conn")

	if err := gonion.BootstrapOneConn(conn); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	t.Log("bootstraped")

	sl := path.New(common.GetGlobalConsensus(), false)

	if err := sl.SelectRandomCircuit(3, 80); err != nil {
		t.Fatal(err)
	}

	c, err = net.Dial("tcp", fmt.Sprintf("%s:%d", sl.Guard().Ipv4Addr, sl.Guard().ORPort))
	if err != nil {
		t.Fatal(err)
	}

	conn, err = gonion.NewConn(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("TOR CONNECTION TO GUARD")

	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ntorHS := &handshakes.Client_NTorHandshake{
		NodeID:    sl.Guard().NodeID,
		KeyID:     sl.Guard().NTorOnionKey,
		PublicKey: pk,
	}

	circ, err := conn.NewCircuit(1, handshakes.HTYPE_NTOR, ntorHS)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("CREATE2 with guardnode")
	for i, v := range sl.Circuit()[1:] {
		addr := fmt.Sprintf("%s:%d", v.Ipv4Addr, v.ORPort)
		t.Logf("loop %d, addr %s", i+2, addr)
		var lspecs []lspec.Lspec
		spec, err := lspec.NewLespecFromIPText(fmt.Sprintf("%s:%d", v.Ipv4Addr, v.ORPort))
		if err != nil {
			t.Fatal(err)
		}
		lspecs = append(lspecs, spec)

		lspecs = append(lspecs, lspec.NewNodeID(v.NodeID))
		lspecs = append(lspecs, lspec.NewEd25519ID(v.IdEd25519))

		pk, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		hs := &handshakes.Client_NTorHandshake{
			NodeID:    v.NodeID,
			KeyID:     v.NTorOnionKey,
			PublicKey: pk,
		}

		t.Log("extending")
		if err := circ.Extend(lspecs, handshakes.HTYPE_NTOR, hs); err != nil {
			t.Fatal(err)
		}
		t.Log("extended")
	}
}
