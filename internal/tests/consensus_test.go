package tests

import (
	"bufio"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"testing"

	gonion2 "git.servidordomal.fun/robogg133/gonion-rewrite"
)

func TestConsensus(t *testing.T) {
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

	req, err := http.NewRequest("GET", "/tor/status-vote/current/consensus-microdesc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(stream); err != nil {
		t.Fatal(err)
	}
	t.Log("Payload wrote")

	t.Log("Starting to read")

	resp, err := http.ReadResponse(bufio.NewReader(stream.Reader), req)
	if err != nil {
		t.Fatal(err)
	}

	consensus, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	os.WriteFile("consensus-microdesc.txt", consensus, 0777)
	sum := sha256.Sum256(consensus)
	consensusFromFast := hex.EncodeToString(sum[:])

	resp, err = http.Get("http://217.196.147.77/tor/status-vote/current/consensus-microdesc")
	if err != nil {
		t.Fatal(err)
	}

	r, err := zlib.NewReader(resp.Body)
	consensusFromAuth, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	sum2 := sha256.Sum256(consensusFromAuth)
	s2 := hex.EncodeToString(sum2[:])

	if s2 != consensusFromFast {
		t.Fatalf("invalid consensus got: (%s), but the consensus from auth dir is (%s) ", consensusFromFast, s2)
	}
	t.Logf("success! consensus digest: %s", consensusFromFast)

}
