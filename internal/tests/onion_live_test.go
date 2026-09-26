package tests

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/embed"
)

func TestEmbedDialOnion(t *testing.T) {
	if os.Getenv("GONION_TEST_ONION") != "1" {
		t.Skip("set GONION_TEST_ONION=1 to run the live onion test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	client, err := embed.New(ctx, embed.Options{
		ORDialer: func(ctx context.Context) (net.Conn, error) {
			return fallback.New(shared.Fallbacks).DialContext(ctx, true)
		},
		GuardDialer: func(ctx context.Context, r *common.RouterStatus) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(r.Ipv4Addr, strconv.Itoa(int(r.ORPort))))
		},
	})
	if err != nil {
		t.Fatalf("embed.New: %v", err)
	}
	defer client.Close()
	// The existing Tor Project onion fixture; redirects are not followed so
	// this proves an HTTP response from the onion stream, not a clearnet redirect.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/", nil)
	if err != nil {
		t.Fatal(err)
	}
	hc := client.HTTPClient()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("onion HTTP: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 || len(body) == 0 {
		t.Fatalf("onion response: status=%d bytes=%d err=%v", resp.StatusCode, len(body), err)
	}
	t.Logf("Tor onion HTTP: status=%d bytes=%d", resp.StatusCode, len(body))
}
