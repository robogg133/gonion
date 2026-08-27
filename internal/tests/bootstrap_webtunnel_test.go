package tests

import (
	"io"
	"testing"

	gonion "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/transports/webtunnel"
)

// webtunnel [2001:db8:6281:baa0:afc0:9579:b303:59a7]:443 377CF6FCBFD2E57D0775EA6F2E8D3EF0D8CDD02F url=https://cryptomeanscryptography.club/TfDS3X50Rf3dR5x3Q3vLS25o ver=0.0.5
func TestBootstrapWebTunnel(t *testing.T) {
	skipIfShort(t)

	c, err := webtunnel.Dial(
		"https://cryptomeanscryptography.club/TfDS3X50Rf3dR5x3Q3vLS25o",
		"", "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	conn, err := gonion.NewConn(c, io.Discard, true)
	if err != nil {
		t.Fatal(err)
	}

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := circuit.GetConsensus(""); err != nil {
		t.Fatal(err)
	}
}
