package snowflake

import (
	"net"
	"os"

	"github.com/rs/zerolog"

	snowflake_client "gitlab.torproject.org/robogg133/snowflake-with-logging-setting/v2/client/lib"
)

const DefaultBroker string = "https://snowflake-broker.torproject.net/"

func DefaultOptions() snowflake_client.ClientConfig {
	logger := zerolog.New(os.Stdout).With().Str("caller", "snowflake").Logger()
	return snowflake_client.ClientConfig{
		BrokerURL:          DefaultBroker,
		KeepLocalAddresses: false,
		UTLSClientID:       "hellofirefox_auto",
		Log:                &logger,
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
