package tests

import (
	"io"
	"net"
	"testing"

	gonion "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/transports/meek"
)

// Official builtin meek bridge (moat circumvention/builtin); the addr is
// ignored by the transport.
var meekBridges = [][2]string{
	{"https://1603026938.rsc.cdn77.org", "www.phpmyadmin.net"},
}

func TestBootstrapMeek(t *testing.T) {
	skipIfShort(t)

	var c net.Conn
	for _, b := range meekBridges {
		conn, err := meek.Dial(b[0], b[1])
		if err == nil {
			c = conn
			break
		}
		t.Logf("bridge %s failed: %v", b[0], err)
	}
	if c == nil {
		t.Fatal("no bridge answered")
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
