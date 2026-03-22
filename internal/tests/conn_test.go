package tests

import (
	"fmt"
	"io"
	"testing"

	gonion2 "git.servidordomal.fun/robogg133/gonion-rewrite"
)

/*
func TestNewConn(t *testing.T) {
	conn, err := gonion2.NewConn("116.255.1.163:9005")
	if err != nil {
		t.Fatal(err)
	}

	if conn == nil {
		t.Log("Connection is nil")
		t.Fail()
	}

	t.Logf("Negotiated protcolversion: %d", conn.ProtcolVersion)
	if err := conn.Close(); err != nil {
		t.Error(err)
	}
}

func TestCreateFastCircuit(t *testing.T) {
	conn, err := gonion2.NewConn("116.255.1.163:9005")
	if err != nil {
		t.Fatal(err)
	}

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		t.Fatal(err)
	}

	if circuit == nil {
		t.Log("Circuit is nil")
		t.Fail()
	}

}
*/

type ReadWrapper struct {
	r io.Reader
}

func (r *ReadWrapper) Read(b []byte) (int, error) {
	fmt.Printf("Buf len %d", len(b))
	readed, err := r.r.Read(b)
	fmt.Printf("Readed %d", readed)
	return readed, err
}

func TestCreateFastCircuitDirStream(t *testing.T) {
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

	stream, err := circuit.NewStream("dir")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Stream open")

	if _, err := stream.Write([]byte("/tor/status-vote/current/consensus-microdesc")); err != nil {
		t.Fatal(err)
	}
	t.Log("Payload wrote")

	t.Log("Starting to read")

	reader := &ReadWrapper{
		r: stream.Reader,
	}

	consensus, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("consensus digest: %x", consensus)

}
