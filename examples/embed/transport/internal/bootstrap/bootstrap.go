// Package bootstrap shares only bootstrap policy and legacy dial cancellation
// between the standalone transport examples. It never enables traffic circuits.
package bootstrap

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/robogg133/gonion/examples/embed/internal/guardstate"
	"github.com/robogg133/gonion/pkg/embed"
)

func Options(fingerprint, guardState string, dial func(context.Context) (net.Conn, error)) (embed.Options, error) {
	id, err := hex.DecodeString(fingerprint)
	if err != nil || len(id) != 20 || [20]byte(id) == [20]byte{} {
		return embed.Options{}, fmt.Errorf("provide -fingerprint with the bridge's expected Tor RSA identity (40 hex digits, not all zero)")
	}
	opts := embed.DefaultOptions()
	opts.Guards, err = guardstate.New(context.Background(), guardState)
	if err != nil {
		return embed.Options{}, err
	}
	opts.BootstrapIdentity = [20]byte(id)
	opts.ORDialer = dial
	// Never inherit a direct traffic dialer from DefaultOptions.
	opts.GuardDialer = nil
	return opts, nil
}

func Run(name, fingerprint, guardState string, timeout time.Duration, dial func(context.Context) (net.Conn, error)) error {
	if timeout <= 0 {
		return fmt.Errorf("provide a positive -timeout")
	}
	opts, err := Options(fingerprint, guardState, dial)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client, err := embed.New(ctx, opts)
	if err != nil {
		return fmt.Errorf("embed.New (%s): %w", name, err)
	}
	defer client.Close()
	log.Printf("authenticated %s consensus over %s; traffic disabled", client.Consensus().Flavor, name)
	return nil
}

// LegacyDialer bounds the caller's wait, not the underlying transport work.
// Late connections are closed; in-flight work may persist until process exit.
// Successful connections belong to embed.New, not the initialization context.
func LegacyDialer(dial func() (net.Conn, error)) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		type result struct {
			conn net.Conn
			err  error
		}
		ready := make(chan result)
		go func() {
			conn, err := dial()
			select {
			case ready <- result{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
		select {
		case r := <-ready:
			return r.conn, r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
