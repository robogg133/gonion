package tests

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/embed"
	"github.com/robogg133/gonion/pkg/transports/snowflake"
)

func snowflakeTestOptions(t *testing.T) embed.Options {
	t.Helper()
	cfg := snowflake.DefaultOptions()
	if s, ok := os.LookupEnv("GONION_SNOWFLAKE_BROKER"); ok {
		cfg.BrokerURL = s
	}
	if s, ok := os.LookupEnv("GONION_SNOWFLAKE_FRONTS"); ok {
		cfg.FrontDomains = nil
		if s != "" {
			cfg.FrontDomains = strings.Split(s, ",")
		}
	}
	if s, ok := os.LookupEnv("GONION_SNOWFLAKE_FINGERPRINT"); ok {
		cfg.BridgeFingerprint = s
	}
	id, err := hex.DecodeString(cfg.BridgeFingerprint)
	if err != nil || len(id) != 20 {
		t.Fatal("invalid Snowflake bridge fingerprint")
	}
	return embed.DefaultBridgeOptions(embed.BridgeOptions{
		Identity:    [20]byte(id),
		DialContext: func(ctx context.Context) (net.Conn, error) { return snowflake.DialContext(ctx, cfg) },
	})
}

// This exercises authenticated bridge bootstrap and actual ntor traffic paths,
// not just transport connectivity. Public-network access is explicitly opt-in.
func TestEmbedDialSnowflake(t *testing.T) {
	if os.Getenv("GONION_TEST_SNOWFLAKE") != "1" {
		t.Skip("set GONION_TEST_SNOWFLAKE=1 for live bridge traffic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	client, err := embed.New(ctx, snowflakeTestOptions(t))
	if err != nil {
		t.Fatalf("Snowflake bootstrap: %v", err)
	}
	defer client.Close()
	if cns := client.Consensus(); !cns.IsAuthenticated() || !cns.IsHydrated() {
		t.Fatal("unverified bootstrap")
	}
	hc := client.HTTPClient()
	defer hc.CloseIdleConnections()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	urls := []string{"https://example.com/"}
	if os.Getenv("GONION_TEST_ONION") == "1" {
		urls = append(urls, "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/")
	}
	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("Snowflake %s: %v", url, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("bridge response: status=%d bytes=%d err=%v", resp.StatusCode, len(body), err)
		}
		t.Logf("Snowflake %s: HTTP %d, %d bytes", url, resp.StatusCode, len(body))
	}
}
