// Command webtunnel bootstraps an embedded client through a WebTunnel bridge.
// Application traffic is disabled; see ../README.md.
package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/robogg133/gonion/examples/embed/transport/internal/bootstrap"
	"github.com/robogg133/gonion/pkg/transports/webtunnel"
)

func main() {
	endpoint := flag.String("url", "", "WebTunnel endpoint URL including its path")
	addr := flag.String("addr", "", "optional TCP endpoint override (host:port)")
	serverName := flag.String("servername", "", "optional TLS server name and HTTP Host override")
	cert := flag.String("cert", "", "optional base64 certificate-chain pin")
	fingerprint := flag.String("fingerprint", "", "expected Tor RSA identity (40 hex digits)")
	state := flag.String("guard-state", "", "caller-owned persistent public-guard state file")
	timeout := flag.Duration("timeout", 3*time.Minute, "bootstrap timeout; underlying transport work may outlive cancellation")
	flag.Parse()
	if *endpoint == "" || flag.NArg() != 0 {
		log.Fatal("provide -url, with no positional arguments")
	}
	dial := bootstrap.LegacyDialer(func() (net.Conn, error) { return webtunnel.Dial(*endpoint, *addr, *serverName, *cert) })
	if err := bootstrap.Run("webtunnel", *fingerprint, *state, *timeout, dial); err != nil {
		log.Fatal(err)
	}
}
