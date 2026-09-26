// Command onion demonstrates reaching a .onion hidden service with pkg/embed.
//
// Client.DialContext detects .onion addresses and routes them through the
// hidden-service rendezvous (pkg/hs); here we expose it through the native
// HTTP client so no SOCKS proxy is needed.
//
// The target onion address is provided via -onion (default: Tor Project's
// public onion website, also used by the opt-in client interoperability test).
//
// Requires outbound access to the Tor network. Run:
//
//	go run ./examples/embed/onion -onion <your-service>.onion
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"time"

	"github.com/robogg133/gonion/pkg/embed"
)

func main() {
	onion := flag.String("onion", "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion", "target .onion address (host only)") // torproject website
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	opts := embed.DefaultOptions()

	client, err := embed.New(ctx, opts)
	if err != nil {
		log.Fatalf("embed.New: %v", err)
	}
	defer client.Close()

	hc := client.HTTPClient()
	url := "http://" + *onion + "/"

	resp, err := hc.Get(url)
	if err != nil {
		log.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		log.Fatalf("copy: %v", err)
	}

}
