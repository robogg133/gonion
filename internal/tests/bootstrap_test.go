package tests

import (
	"fmt"
	"testing"

	"github.com/robogg133/gonion"
	gonion2 "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
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

}
