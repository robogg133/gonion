package tests

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"testing"

	gonion2 "github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
)

func TestConsensus(t *testing.T) {
	t.Parallel()

	c, err := fallback.Dial(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("selected address from fallback", c.RemoteAddr().String())

	conn, err := gonion2.NewConn(c, io.Discard, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created conn")

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created circuit")

	stream, err := circuit.NewStream("dir", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Stream open")

	req, err := http.NewRequest("GET", gonion2.HTTP_PATH_CONSENSUS_MICRODESC, nil)
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

	t.Logf("success! consensus digest: %s", consensusFromFast)

}
