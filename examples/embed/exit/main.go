// Command exit demonstrates raw TCP dialing through pkg/embed.
//
// Instead of going through http.Client, it opens a plain exit stream with
// Client.DialContext and writes an HTTP/1.0 request by hand. This shows the
// net.Conn returned is a real connection tunneled through a Tor exit circuit.
//
// Requires outbound access to the Tor network. Run:
//
//	go run ./examples/embed/exit
package main

import (
	"context"
	"io"
	"log"
	"os"
	"time"

	"github.com/robogg133/gonion/pkg/embed"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	opts := embed.DefaultOptions()

	client, err := embed.New(ctx, opts)
	if err != nil {
		log.Fatalf("embed.New: %v", err)
	}
	defer client.Close()

	hc := client.HTTPClient()
	resp, err := hc.Get("https://example.com")
	if err != nil {
		log.Fatalf("GET example.com: %v", err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		log.Fatalf("read response: %v", err)
	}
}
