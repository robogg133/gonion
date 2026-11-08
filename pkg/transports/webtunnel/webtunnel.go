package webtunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/transport/httpupgrade"
	wtls "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/transport/tls"
)

// Dial connects to a webtunnel bridge through an HTTPS WebSocket-upgrade
// tunnel. It is DialContext with a background context, so it waits without
// cancellation for the endpoint, TLS handshake, and upgrade to complete.
//
// bridgeURL is the bridge endpoint URL ("https://host[:port]/path",
// the url= argument of the bridge line).
//
// addr optionally overrides the dialed TCP endpoint ("host:port"), mirroring
// the leading <IP>:<PORT> of the Bridge line, which the upstream PT client
// discards; useful when the url hostname does not resolve. When empty, the
// URL hostname is resolved (skipping private/loopback addresses, like
// upstream). There is no fallback: when addr is set, only that endpoint is
// dialed.
//
// serverName optionally overrides the TLS server name and Host header.
// cert optionally pins the peer certificate chain hash (base64, as in the
// cert= argument of the bridge line; also enables self-signed certificates,
// like upstream).
func Dial(bridgeURL, addr, serverName, cert string) (net.Conn, error) {
	return DialContext(context.Background(), bridgeURL, addr, serverName, cert)
}

// DialContext connects as Dial, honoring ctx at every stage: hostname
// resolution, TCP establishment, the TLS handshake, and the blocking
// WebSocket-upgrade request. The upstream webtunnel transports accept no
// context, so cancellation interrupts their in-flight reads and writes by
// closing the underlying TCP connection; a canceled dial then fails with
// ctx.Err() and never returns a half-initialized or late connection.
//
// After a successful return, ownership of the connection transfers to the
// caller and ctx no longer controls its lifetime.
func DialContext(ctx context.Context, bridgeURL, addr, serverName, cert string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u, err := url.Parse(bridgeURL)
	if err != nil {
		return nil, fmt.Errorf("webtunnel: parse url failed: %w", err)
	}

	useTLS := false
	defaultPort := "80"
	switch u.Scheme {
	case "https":
		useTLS, defaultPort = true, "443"
	case "http":
	default:
		return nil, fmt.Errorf("webtunnel: unsupported scheme %q", u.Scheme)
	}

	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	host := u.Hostname()
	if serverName == "" {
		serverName = host
	}

	raw, err := dialTCP(ctx, host, port, addr)
	if err != nil {
		return nil, err
	}

	// Closing the raw endpoint is the only way to interrupt the upstream
	// handshake and upgrade transports; stop the guard once the connection
	// is handed to the caller.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()

	conn, err := finishClient(ctx, raw, u, serverName, cert, useTLS)
	stop()
	if ctx.Err() != nil {
		// Cancellation raced a successful phase; the connection is late.
		if conn != nil {
			_ = conn.Close()
		}
		_ = raw.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// dialTCP opens the TCP endpoint without any policy fallback: addr is
// authoritative when set, otherwise the URL hostname is resolved and filtered
// like the upstream PT client.
func dialTCP(ctx context.Context, host, port, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	if addr != "" {
		return d.DialContext(ctx, "tcp", addr)
	}
	addrs, lookupErr := lookup(ctx, host, port)
	if lookupErr != nil {
		return nil, lookupErr
	}
	for _, a := range addrs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if conn, dialErr := d.DialContext(ctx, "tcp", a); dialErr == nil {
			return conn, nil
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, fmt.Errorf("webtunnel: cannot connect to %v", addrs)
}

// finishClient performs the TLS and HTTP-upgrade client handshakes over raw.
// It never closes raw; the caller owns cleanup.
func finishClient(ctx context.Context, raw net.Conn, u *url.URL, serverName, cert string, useTLS bool) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn := raw
	if useTLS {
		conf := &wtls.Config{ServerName: serverName}
		if cert != "" {
			pin, decodeErr := base64.StdEncoding.DecodeString(cert)
			if decodeErr != nil {
				return nil, fmt.Errorf("webtunnel: decode cert chain hash failed: %w", decodeErr)
			}
			conf.AllowInsecure = true
			conf.PinnedPeerCertificateChainSha256 = [][]byte{pin}
		}
		tlsTransport, tlsErr := wtls.NewTLSTransport(conf)
		if tlsErr != nil {
			return nil, tlsErr
		}
		tlsConn, tlsErr := tlsTransport.Client(conn)
		if tlsErr != nil {
			return nil, tlsErr
		}
		// Upstream defers the handshake to the first I/O. Completing it here
		// lets ctx bound it and surfaces a pin or certificate failure at dial
		// time instead of inside an opaque later read.
		if handshake, ok := tlsConn.(interface {
			HandshakeContext(context.Context) error
		}); ok {
			if hsErr := handshake.HandshakeContext(ctx); hsErr != nil {
				return nil, hsErr
			}
		}
		conn = tlsConn
	}

	upTransport, upErr := httpupgrade.NewHTTPUpgradeTransport(&httpupgrade.Config{
		Path: strings.TrimPrefix(u.EscapedPath(), "/"),
		Host: serverName,
	})
	if upErr != nil {
		return nil, upErr
	}
	// Client blocks writing the request and reading the 101 reply; the
	// caller's AfterFunc guard closes raw to unblock it on cancellation.
	return upTransport.Client(conn)
}

func lookup(ctx context.Context, hostname, port string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("webtunnel: lookup %s failed: %w", hostname, err)
	}
	var addrs []string
	for _, ip := range ips {
		a := net.ParseIP(ip)
		if a == nil || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsPrivate() {
			continue
		}
		if a.To4() != nil {
			addrs = append(addrs, ip+":"+port)
		} else {
			addrs = append(addrs, "["+ip+"]:"+port)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("webtunnel: no usable address for %s", hostname)
	}
	return addrs, nil
}
