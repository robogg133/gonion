package tests

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/embed"
)

func TestEmbedDialOnion(t *testing.T) {
	if os.Getenv("GONION_TEST_ONION") != "1" {
		t.Skip("set GONION_TEST_ONION=1 to run the live onion test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client, err := embed.New(ctx, embed.Options{ORDialer: func(context.Context) (net.Conn, error) {
		return fallback.New(shared.Fallbacks).Dial(true)
	}})
	if err != nil {
		t.Fatalf("embed.New: %v", err)
	}
	defer client.Close()
	conn, err := client.DialContext(ctx, "tcp", "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:80")
	if err != nil {
		t.Fatalf("dial onion: %v", err)
	}
	conn.Close()
}
