package main

import (
	"context"
	"encoding/hex"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/robogg133/gonion/examples/embed/transport/internal/bootstrap"
)

func TestBootstrapPolicy(t *testing.T) {
	const pin = "0123456789ABCDEF0123456789ABCDEF01234567"
	dial := bootstrap.LegacyDialer(func() (net.Conn, error) { t.Error("unexpected network attempt"); return nil, nil })
	state := filepath.Join(t.TempDir(), "guards.json")
	opts, err := bootstrap.Options(pin, state, dial)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(pin)
	if opts.BootstrapIdentity != [20]byte(want) || opts.ORDialer == nil || opts.GuardDialer != nil || opts.Storage != nil {
		t.Fatal("unsafe bootstrap options")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := opts.ORDialer(ctx); conn != nil || err != context.Canceled {
		t.Fatalf("pre-canceled dial: %v, %v", conn, err)
	}
	if err := bootstrap.Run("test", pin, state, 0, dial); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	if err := bootstrap.Run("test", "", state, time.Second, dial); err == nil {
		t.Fatal("invalid pin accepted")
	}
}
