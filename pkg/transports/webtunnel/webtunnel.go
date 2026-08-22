package webtunnel

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/transport/httpupgrade"
	wtls "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/transport/tls"
)

// Dial connects to a webtunnel bridge through an HTTPS WebSocket-upgrade
// tunnel. bridgeURL is the bridge endpoint URL ("https://host[:port]/path",
// the url= argument of the bridge line).
//
// addr optionally overrides the dialed TCP endpoint ("host:port"), mirroring
// the leading <IP>:<PORT> of the Bridge line, which the upstream PT client
// discards; useful when the url hostname does not resolve. When empty, the
// URL hostname is resolved (skipping private/loopback addresses, like
// upstream).
//
// serverName optionally overrides the TLS server name and Host header.
// cert optionally pins the peer certificate chain hash (base64, as in the
// cert= argument of the bridge line; also enables self-signed certificates,
// like upstream).
func Dial(bridgeURL, addr, serverName, cert string) (net.Conn, error) {
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

	var conn net.Conn
	if addr != "" {
		conn, err = net.Dial("tcp", addr)
	} else {
		addrs, lookupErr := lookup(host, port)
		if lookupErr != nil {
			return nil, lookupErr
		}
		for _, a := range addrs {
			if c, dialErr := net.Dial("tcp", a); dialErr == nil {
				conn, err = c, nil
				break
			}
		}
		if conn == nil {
			err = fmt.Errorf("webtunnel: cannot connect to %v", addrs)
		}
	}
	if err != nil {
		return nil, err
	}

	if useTLS {
		conf := &wtls.Config{ServerName: serverName}
		if cert != "" {
			pin, decodeErr := base64.StdEncoding.DecodeString(cert)
			if decodeErr != nil {
				conn.Close()
				return nil, fmt.Errorf("webtunnel: decode cert chain hash failed: %w", decodeErr)
			}
			conf.AllowInsecure = true
			conf.PinnedPeerCertificateChainSha256 = [][]byte{pin}
		}
		tlsTransport, tlsErr := wtls.NewTLSTransport(conf)
		if tlsErr != nil {
			conn.Close()
			return nil, tlsErr
		}
		tlsConn, tlsErr := tlsTransport.Client(conn)
		if tlsErr != nil {
			conn.Close()
			return nil, tlsErr
		}
		conn = tlsConn
	}

	upTransport, upErr := httpupgrade.NewHTTPUpgradeTransport(&httpupgrade.Config{
		Path: strings.TrimPrefix(u.EscapedPath(), "/"),
		Host: serverName,
	})
	if upErr != nil {
		conn.Close()
		return nil, upErr
	}
	upConn, upErr := upTransport.Client(conn)
	if upErr != nil {
		conn.Close()
		return nil, upErr
	}
	return upConn, nil
}

func lookup(hostname, port string) ([]string, error) {
	ips, err := net.LookupHost(hostname)
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
