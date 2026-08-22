package snowflake

import (
	"io"
	"log"
	"net"

	snowflake_client "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"
)

const DefaultBroker string = "https://snowflake-broker.torproject.net/"

func DefaultOptions() snowflake_client.ClientConfig {
	log.SetOutput(io.Discard)
	return snowflake_client.ClientConfig{
		BrokerURL:          DefaultBroker,
		KeepLocalAddresses: false,
		UTLSClientID:       "hellofirefox_auto",
	}
}

// addr mirrors the other transports' Dial signature; snowflake resolves its
// endpoint via the broker (and optionally cfg.BridgeFingerprint), not via addr.
func Dial(cfg snowflake_client.ClientConfig) (net.Conn, error) {
	transport, err := snowflake_client.NewSnowflakeClient(cfg)
	if err != nil {
		return nil, err
	}
	return transport.Dial()
}
