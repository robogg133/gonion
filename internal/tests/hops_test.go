package tests

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
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

	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ntorHS := &handshakes.Client_NTorHandshake{
		NodeID:     sl.Guard().NodeID,
		KeyID:      sl.Guard().NTorOnionKey,
		PrivateKey: sk,
		PublicKey:  sk.PublicKey(),
	}

	circ, err := conn.NewCircuit(1, handshakes.HTYPE_NTOR, ntorHS)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("CREATE2 with guardnode")
	t.Log("Testing connection with guardnode")
	t.Run("TestGuardNode", func(t *testing.T) {
		if _, err := circ.GetConsensus(); err != nil {
			t.Fatal(err)
		}
		t.Log("success")
	})
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

		sk, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		hs := &handshakes.Client_NTorHandshake{
			NodeID:     v.NodeID,
			KeyID:      v.NTorOnionKey,
			PrivateKey: sk,
			PublicKey:  sk.PublicKey(),
		}

		t.Log("extending")
		if err := circ.Extend(lspecs, handshakes.HTYPE_NTOR, hs); err != nil {
			t.Fatal(err)
		}
		t.Log("extended")
	}

	stream, err := circ.NewStream("servidordomal.lol:80", circ.HopCount()-1)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Free()
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := req.Write(stream); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(stream.Reader), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(t.Output(), resp.Body); err != nil {
		t.Fatal(err)
	}
}
