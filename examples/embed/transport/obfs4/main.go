// Command obfs4 bootstraps an embedded client through an obfs4 bridge.
// Application traffic is disabled; see ../README.md.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"time"

	"github.com/robogg133/gonion/examples/embed/transport/internal/bootstrap"
	"github.com/robogg133/gonion/pkg/transports/obfs4"
)

func main() {
	addr := flag.String("addr", "", "obfs4 bridge endpoint (host:port)")
	nodeID := flag.String("nodeid", "", "obfs4 bridge node ID")
	cert := flag.String("cert", "", "obfs4 bridge certificate")
	iatMode := flag.String("iatmode", "0", "obfs4 iat-mode")
	fingerprint := flag.String("fingerprint", "", "expected Tor RSA identity (40 hex digits)")
	state := flag.String("guard-state", "", "caller-owned persistent public-guard state file")
	timeout := flag.Duration("timeout", 3*time.Minute, "bootstrap timeout")
	flag.Parse()
	if *addr == "" || *nodeID == "" || *cert == "" || flag.NArg() != 0 {
		log.Fatal("provide -addr, -nodeid and -cert, with no positional arguments")
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		return obfs4.DialContext(ctx, *addr, *nodeID, *cert, *iatMode)
	}
	if err := bootstrap.Run("obfs4", *fingerprint, *state, *timeout, dial); err != nil {
		log.Fatal(err)
	}
}
