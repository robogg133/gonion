// Snowflake carries both bootstrap and every traffic circuit through one pinned
// bridge. No local proxy, external Tor daemon, or direct guard fallback is used.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/robogg133/gonion/pkg/embed"
	"github.com/robogg133/gonion/pkg/transports/snowflake"
)

func main() {

	cfg := snowflake.DefaultOptions()

	id, err := hex.DecodeString(cfg.BridgeFingerprint)
	if err != nil || len(id) != 20 {
		panic("fingerprint must contain 40 hexadecimal digits")
	}
	cfg.FrontDomains, cfg.ICEAddresses = nil, nil

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	opts := embed.DefaultBridgeOptions(embed.BridgeOptions{
		Identity: [20]byte(id),
		DialContext: func(ctx context.Context) (net.Conn, error) {
			return snowflake.DialContext(ctx, cfg)
		},
	})
	client, err := embed.New(ctx, opts)
	if err != nil {
		panic(fmt.Errorf("bootstrap through Snowflake: %w", err))
	}
	defer client.Close()
	hc := client.HTTPClient()
	defer hc.CloseIdleConnections()
	resp, err := hc.Get("https://example.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("HTTP status: %s", resp.Status))
	}
	if _, err = io.Copy(os.Stdout, io.LimitReader(resp.Body, 1<<20)); err != nil {
		panic(err)
	}

}
