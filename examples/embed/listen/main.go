// Command listen publishes a temporary onion service and serves HTTP directly
// on Tor streams. It does not open a local listening socket or save any keys.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"sync/atomic"
	"time"

	"github.com/robogg133/gonion/pkg/embed"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	init, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	opts := embed.DefaultOptions()

	client, err := embed.New(init, opts)
	if err != nil {
		return err
	}
	defer client.Close()
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// Safe only because the identity is new and discarded on every run. A
	// reusable identity requires durable, atomic reservation before return.
	var revision atomic.Uint64
	listener, err := client.Listen(init, embed.ServiceOptions{
		Identity: identity,
		Port:     99,
		NextRevision: func(ctx context.Context, _ [32]byte) (uint64, error) {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			return revision.Add(1), nil
		},
	})
	clear(identity)
	if err != nil {
		return err
	}
	defer listener.Close()
	cancel() // Initialization does not own the returned listener's lifetime.

	log.Printf("published %s", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer log.Printf("closed %s", conn.RemoteAddr())
			defer conn.Close()
			log.Printf("accepted %s", conn.RemoteAddr())
			if _, err := io.Copy(conn, conn); err != nil {
				log.Printf("copy error: %v", err)
			}
		}()

	}

}
