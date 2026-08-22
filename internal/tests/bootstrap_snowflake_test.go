package tests

import (
	"io"
	"testing"

	gonion "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/transports/snowflake"
)

func TestBootstrapSnowflake(t *testing.T) {
	skipIfShort(t)

	c, err := snowflake.Dial(snowflake.DefaultOptions())
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

	if _, err := circuit.GetConsensus(); err != nil {
		t.Fatal(err)
	}
}
