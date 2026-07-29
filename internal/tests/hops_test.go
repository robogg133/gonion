package tests

import (
	"bufio"
	"io"
	"net/http"
	"testing"

	"github.com/robogg133/gonion/pkg/path"
)

// TestConnect is the end-to-end 3-hop path: bootstrap → circuit → clearnet HTTP.
func TestConnect(t *testing.T) {
	skipIfShort(t)

	cns := bootstrapConsensus(t)
	sl := path.New(cns, false)
	if err := sl.SelectRandomCircuit(3, 80); err != nil {
		t.Fatal(err)
	}
	for i, r := range sl.Circuit() {
		t.Logf("hop%d %s %s:%d", i, r.Nickname, r.Ipv4Addr, r.ORPort)
	}

	status, n := exitGET(t, cns, "example.com:80", "example.com")
	t.Logf("GET example.com status=%d bytes=%d", status, n)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if n < 50 {
		t.Fatalf("short body %d", n)
	}

	// Also exercise directory stream on a fresh 3-hop circuit.
	circ, conn, err := dialPath(sl.Circuit())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer circ.Close()

	t.Run("GuardDir", func(t *testing.T) {
		if _, err := circ.GetConsensus(); err != nil {
			t.Fatal(err)
		}
	})

	// Smoke: second stream on same circuit.
	stream, err := circ.Dial("example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	if err := req.Write(stream); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second stream status %s", resp.Status)
	}
}
