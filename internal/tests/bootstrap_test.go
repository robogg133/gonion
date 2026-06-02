package tests

import (
	"fmt"
	"testing"

	"github.com/robogg133/gonion"
	gonion2 "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/path"
)

func TestMicrodesc(t *testing.T) {

	dialer := fallback.New(shared.Fallbacks)

	c, err := dialer.Dial(true)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Using addr %s from fallback dirs\n", c.RemoteAddr().String())

	conn, err := gonion2.NewConn(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created conn")

	if err := gonion.BootstrapOneConn(conn); err != nil {
		t.Fatal(err)
	}

	sl := path.New(common.GetGlobalConsensus(), false)

	if err := sl.SelectRandomCircuit(3, 80); err != nil {
		t.Fatal(err)
	}

	for _, v := range sl.Circuit() {
		t.Logf("Node %s IP %s\n", v.Nickname, v.Ipv4Addr)
	}

	conn.Close()

}
