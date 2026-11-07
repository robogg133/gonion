// Command meek bootstraps an embedded client through a meek bridge.
// Application traffic is disabled; see ../README.md.
package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/robogg133/gonion/examples/embed/transport/internal/bootstrap"
	"github.com/robogg133/gonion/pkg/transports/meek"
)

func main() {
	endpoint := flag.String("url", "", "meek endpoint URL")
	front := flag.String("front", "", "optional front domain")
	fingerprint := flag.String("fingerprint", "", "expected Tor RSA identity (40 hex digits)")
	state := flag.String("guard-state", "", "caller-owned persistent public-guard state file")
	timeout := flag.Duration("timeout", 3*time.Minute, "bootstrap timeout; underlying transport work may outlive cancellation")
	flag.Parse()
	if *endpoint == "" || flag.NArg() != 0 {
		log.Fatal("provide -url, with no positional arguments")
	}
	dial := bootstrap.LegacyDialer(func() (net.Conn, error) { return meek.Dial(*endpoint, *front) })
	if err := bootstrap.Run("meek", *fingerprint, *state, *timeout, dial); err != nil {
		log.Fatal(err)
	}
}
