package tests

import (
	"fmt"
	"testing"

	gonion2 "git.servidordomal.fun/robogg133/gonion"
	"git.servidordomal.fun/robogg133/gonion/pkg/transports/obfs4"
)

// obfs4 93.177.73.226:24852 99ED350316AFC4ED1964CFE9EC84C201416D143D cert=KciXEUlkxmOHsVFLh6s3fAEWO7p0GHt6jhhTj/XaWM8/VmCYqbzPmRM+Q4PA1AcJ8JyWBA iat-mode=0
func TestMicrodescObfs4(t *testing.T) {
	c, err := obfs4.Dial("93.177.73.226:24852", "99ED350316AFC4ED1964CFE9EC84C201416D143D", "KciXEUlkxmOHsVFLh6s3fAEWO7p0GHt6jhhTj/XaWM8/VmCYqbzPmRM+Q4PA1AcJ8JyWBA", "0")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := gonion2.NewConn(c)
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

	for _, v := range desc {
		if v.ExitRules == nil {
			fmt.Println(false)
			continue
		}
		fmt.Println(v.ExitRules.IsAllowed(80))

	}

}
