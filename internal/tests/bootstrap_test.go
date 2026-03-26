package tests

import (
	"testing"

	gonion2 "git.servidordomal.fun/robogg133/gonion"
)

func TestMicrodesc(t *testing.T) {
	conn, err := gonion2.NewConn("38.102.127.252:9004")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created conn")

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created circuit")

	cns, err := circuit.GetConsensus()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Got consensus")

	var a []string

	for i := range 91 {
		a = append(a, cns.RelayInformation[i].MicrodescriptorDigest)
	}

	desc, err := circuit.GetMicrodescriptors(a)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Got microdescriptors")

	if len(desc) != 91 {
		t.Fatal(err)
	}

}
