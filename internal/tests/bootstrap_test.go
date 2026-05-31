package tests

import (
	"fmt"
	"testing"

	"github.com/robogg133/gonion"
	gonion2 "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/common"
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
	fmt.Println("nigger")

	for _, v := range common.GetGlobalConsensus().RelayInformation {
		if v.StatusFlags[common.FLAG_GUARD] {
			fmt.Printf("%s:%d\n", v.Ipv4Addr, v.ORPort)
			fmt.Println(v.NTorOnionKey)
			fmt.Println(v.NodeID)
		}
	}

	conn.Close()

}
