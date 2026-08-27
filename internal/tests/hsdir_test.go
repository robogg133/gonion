package tests

import (
	"net/http"
	"testing"

	"github.com/robogg133/gonion"
	"github.com/robogg133/gonion/pkg/path"
)

func TestOnion(t *testing.T) {
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
	circ, conn, err := dialPathWithRetry(t, cns)
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	defer conn.Close()

	t.Run("GuardDir", func(t *testing.T) {
		if _, err := circ.GetConsensus(gonion.ConsensusFlavorMicrodesc); err != nil {
			t.Fatal(err)
		}
	})

	// Smoke: second stream on same circuit.
	if _, err := circ.Dial("tbup4alxvo3wmessgrbjfbfpny6x5xab56do6sli6i6b42sgreisrfqd.onion"); err != nil {
		t.Fatal(err)
	}
}
