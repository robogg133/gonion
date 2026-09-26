package tests

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"

	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/embed"
)

func TestEmbedDialExit(t *testing.T) {
	skipIfShort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client, err := embed.New(ctx, embed.Options{
		GuardDialer: func(ctx context.Context, r *common.RouterStatus) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(r.Ipv4Addr, strconv.Itoa(int(r.ORPort))))
		},
		ORDialer: func(ctx context.Context) (net.Conn, error) {
			return fallback.New(shared.Fallbacks).DialContext(ctx, true)
		},
	})
	if err != nil {
		t.Fatalf("embed.New: %v", err)
	}
	defer client.Close()

	conn, err := client.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	t.Log("dialed example.com:80 ok")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("HTTPS response: status=%d bytes=%d err=%v", resp.StatusCode, len(body), err)
	}
	t.Logf("Tor HTTPS: status=%d bytes=%d", resp.StatusCode, len(body))
}
