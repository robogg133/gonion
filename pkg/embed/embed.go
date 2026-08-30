package embed

import (
	"context"
	"net"
	"net/http"
)

// HTTPClient returns an *http.Client whose Transport dials through this client
// (no SOCKS, no localhost proxy — coherent with the README "Native Dialer").
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:    c.DialContext,
			DialTLSContext: c.DialTLSContext,
			// Hidden services and exit streams are already end-to-end through
			// Tor; let the transport skip its own TLS verification only when the
			// caller explicitly opts in via a custom Transport.
		},
	}
}

// ensure the interface is satisfied (net.Dialer contract).
var (
	_ interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	} = (*Client)(nil)
)
