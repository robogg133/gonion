// Command snowflake bootstraps an embedded client through Snowflake.
// Application traffic is disabled; see ../README.md.
package main

import (
	"flag"
	"log"
	"net"
	"strings"
	"time"

	"github.com/robogg133/gonion/examples/embed/transport/internal/bootstrap"
	"github.com/robogg133/gonion/pkg/transports/snowflake"
)

func main() {
	broker := flag.String("broker", snowflake.DefaultBroker, "Snowflake broker URL")
	front := flag.String("front", "", "optional front domain")
	ice := flag.String("ice", "", "comma-separated STUN/TURN URLs")
	fingerprint := flag.String("fingerprint", "", "expected Tor RSA identity (40 hex digits)")
	state := flag.String("guard-state", "", "caller-owned persistent public-guard state file")
	timeout := flag.Duration("timeout", 3*time.Minute, "bootstrap timeout; underlying transport work may outlive cancellation")
	flag.Parse()
	if *broker == "" || *ice == "" || flag.NArg() != 0 {
		log.Fatal("provide -broker and -ice, with no positional arguments")
	}
	addresses := strings.Split(*ice, ",")
	for i := range addresses {
		addresses[i] = strings.TrimSpace(addresses[i])
		if addresses[i] == "" {
			log.Fatal("provide -ice without empty entries")
		}
	}
	cfg := snowflake.DefaultOptions()
	cfg.BrokerURL = *broker
	cfg.FrontDomains = nil // This command's -front overrides the preset fronts.
	cfg.FrontDomain = *front
	cfg.BridgeFingerprint = *fingerprint
	cfg.ICEAddresses = addresses
	dial := bootstrap.LegacyDialer(func() (net.Conn, error) { return snowflake.Dial(cfg) })
	if err := bootstrap.Run("snowflake", *fingerprint, *state, *timeout, dial); err != nil {
		log.Fatal(err)
	}
}
