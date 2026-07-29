package gonion

import (
	"context"
	"crypto/tls"
	"net"
)

type gonionTransport struct {
	circ *Circuit
}

func (g *gonionTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return g.circ.Dial(addr)
}

func (g *gonionTransport) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := g.circ.Dial(addr)
	if err != nil {
		return nil, err
	}
	return tls.Client(conn, &tls.Config{ServerName: hostOf(addr)}), nil
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
