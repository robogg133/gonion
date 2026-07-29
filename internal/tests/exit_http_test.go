package tests

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/path"
)

// TestExitHTTP builds a 3-hop circuit and GETs check.torproject.org via the exit.
func TestExitHTTP(t *testing.T) {
	skipIfShort(t)
	cns := bootstrapConsensus(t)
	status, n := exitGET(t, cns, "check.torproject.org:80", "check.torproject.org")
	t.Logf("check.torproject.org status=%d bytes=%d", status, n)
	// 200 or redirect both prove exit TCP works.
	if status != http.StatusOK && status != http.StatusMovedPermanently && status != http.StatusFound && status != http.StatusSeeOther {
		t.Fatalf("unexpected status %d", status)
	}
}

// TestExitHTTPExample fetches example.com through Tor.
func TestExitHTTPExample(t *testing.T) {
	skipIfShort(t)
	cns := bootstrapConsensus(t)
	status, n := exitGET(t, cns, "example.com:80", "example.com")
	t.Logf("example.com status=%d bytes=%d", status, n)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if n < 100 {
		t.Fatalf("body too short: %d", n)
	}
}

func exitGET(t *testing.T, cns *common.Consensus, addr, host string) (status int, bodyLen int64) {
	t.Helper()

	const attempts = 3
	var last error
	for range attempts {
		sl := path.New(cns, false)
		if err := sl.SelectRandomCircuit(3, 80); err != nil {
			t.Fatal(err)
		}
		relays := sl.Circuit()
		t.Logf("path %s -> %s -> %s", relays[0].Nickname, relays[1].Nickname, relays[2].Nickname)

		circ, conn, err := dialPath(relays)
		if err != nil {
			last = err
			t.Logf("path failed: %v", err)
			continue
		}
		defer conn.Close()
		defer circ.Close()

		stream, err := circ.Dial(addr)
		if err != nil {
			last = err
			t.Logf("dial %s failed: %v", addr, err)
			continue
		}
		defer stream.Close()

		req, err := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.Header.Set("User-Agent", "gonion-test/1.0")

		if err := req.Write(stream); err != nil {
			last = err
			t.Logf("write request failed: %v", err)
			continue
		}

		resp, err := http.ReadResponse(bufio.NewReader(stream), req)
		if err != nil {
			last = err
			t.Logf("read response failed: %v", err)
			continue
		}
		n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		return resp.StatusCode, n
	}
	t.Fatalf("exit GET %s failed after %d attempts: %v", addr, attempts, last)
	return 0, 0
}

func dialPath(relays []*common.RouterStatus) (*gonion.Circuit, *gonion.Conn, error) {
	guard := relays[0]
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", guard.Ipv4Addr, guard.ORPort), 15*time.Second)
	if err != nil {
		return nil, nil, err
	}
	conn, err := gonion.NewConn(raw, io.Discard, false)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	circ, err := conn.BuildPath(1, relays)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return circ, conn, nil
}

func bootstrapConsensus(t *testing.T) *common.Consensus {
	t.Helper()
	if cns := common.GetGlobalConsensus(); cns != nil && len(cns.RelayInformation) > 100 {
		return cns
	}

	dialer := fallback.New(shared.Fallbacks)
	raw, err := dialer.Dial(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bootstrap via %s", raw.RemoteAddr())

	conn, err := gonion.NewConn(raw, io.Discard, false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := gonion.BootstrapOneConn(conn); err != nil {
		t.Fatal(err)
	}
	cns := common.GetGlobalConsensus()
	if cns == nil {
		t.Fatal("no global consensus after bootstrap")
	}
	return cns
}
