package tests

import (
	"net"
	"testing"

	"github.com/robogg133/gonion"
	gonion2 "github.com/robogg133/gonion"
)

func TestMicrodesc(t *testing.T) {

	c, err := net.Dial("tcp", "109.70.100.245:443")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := gonion2.NewConn(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created conn")

	if err := gonion.BootstrapOneConn(conn); err != nil {
		t.Fatal(err)
	}

}
