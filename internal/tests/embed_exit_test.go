package tests

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/embed"
)

func TestEmbedDialExit(t *testing.T) {
	skipIfShort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client, err := embed.New(ctx, embed.Options{
		ORDialer: func(ctx context.Context) (net.Conn, error) {
			return fallback.New(shared.Fallbacks).Dial(true)
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
}
