package gonion_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/robogg133/gonion"
)

func TestNewConn(t *testing.T) {

	relayConn, err := gonion.NewConn("23.141.188.38:443")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Creating circuit")
	circuit, err := relayConn.NewFastCircuit(1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Circuit created")

	fmt.Println("Creating stream")
	stream, err := circuit.NewStream("dir")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Stream created")

	fmt.Println("Writing Payload")
	if _, err := stream.Write([]byte("GET /tor/status-vote/current/consensus-microdesc HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	fmt.Println("Wrote the payload")

	fmt.Println("Reading from pipe")

	b, err := io.ReadAll(stream)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string(b))

}
