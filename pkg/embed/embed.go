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
			DialContext: c.DialContext,
			// Leave TLS to net/http so caller TLSClientConfig and handshake
			// timeouts are honored. Proxy is nil: never use environment proxies.
		},
	}
}

// ensure the interface is satisfied (net.Dialer contract).
var (
	_ interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	} = (*Client)(nil)
)
