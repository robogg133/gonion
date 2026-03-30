package tests

import (
	"net"
	"testing"

	"git.servidordomal.fun/robogg133/gonion"
	gonion2 "git.servidordomal.fun/robogg133/gonion"
)

func TestMicrodesc(t *testing.T) {

	c, err := net.Dial("tcp", "38.102.127.252:9004")
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
