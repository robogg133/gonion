// Package snowflake adapts the pinned Snowflake client library to a
// context-aware bridge dialer for Gonion.
//
// Upstream provenance (E4.4): this uses the fork
// gitlab.torproject.org/robogg133/snowflake-with-logging-setting/v2 at
// pseudo-version v2.14.2-0.20261002001353-aff631a5b504 (commit aff631a5b504,
// 2026-10-02), a fork of
// gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2
// v2.14.1 that adds a configurable zerolog logger. Gonion does not vendor
// upstream sources; go.mod records the exact pin.
//
// Third-party exposure differs by configuration and must not be conflated:
//
//   - Fronted (DefaultOptions): broker polling is HTTPS domain-fronting over
//     one of FrontDomains (CDN77 / phpMyAdmin presets). DNS and TCP/QUIC
//     reach the fronting CDN; the broker hostname is carried in encrypted
//     request metadata per the upstream protocol. The uTLS ClientHello
//     ("hellorandomizedalpn") imitates a browser hello to the front.
//   - Unfronted (UnfrontedOptions, FrontDomains cleared): polling talks
//     directly to BrokerURL. DNS, TCP, and the TLS SNI all disclose the
//     broker endpoint to any network observer.
//   - Both modes: NAT-type probing and ICE gathering contact the listed
//     STUN servers over UDP (the defaults are eight public STUN hosts; the
//     library shuffles and uses a subset). The data path is a WebRTC
//     datachannel (DTLS) to volunteer Snowflake proxies, potentially over
//     UDP with peer addresses derived via ICE; TURN relays are accepted by
//     the ICE parser if configured but are not part of the defaults.
//     KeepLocalAddresses=false strips local addresses from the SDP offer.
//
// "No direct Tor guard fallback" is therefore not "no direct networking":
// the broker, STUN hosts, CDN front, and volunteer proxies are all
// third-party endpoints and are all visible to the local network. Nothing
// here is evidence of censorship resistance; only configurations with
// current opt-in evidence (see pkg/embed README and internal/tests) are
// documented as validated.
package snowflake

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog"

	snowflake_client "gitlab.torproject.org/robogg133/snowflake-with-logging-setting/v2/client/lib"
)

// Defaults follow client/torrc in the pinned Snowflake dependency (aff631a5b504).
// These are public service endpoints, not an availability/censorship guarantee.
const DefaultBroker = "https://1098762253.rsc.cdn77.org/"
const DefaultBridgeFingerprint = "2B280B23E1107BB62ABFC40DDCC8824814F80A72"

// UpstreamVersion records the exact pinned fork pseudo-version for
// transport-specific evidence reporting (E4.4).
const UpstreamVersion = "v2.14.2-0.20261002001353-aff631a5b504"

// DefaultOptions returns the fronted configuration: domain-fronted broker
// polling over FrontDomains, public STUN ICE servers, and a silent logger.
func DefaultOptions() snowflake_client.ClientConfig {
	logger := zerolog.Nop()
	return snowflake_client.ClientConfig{
		BrokerURL:         DefaultBroker,
		BridgeFingerprint: DefaultBridgeFingerprint,
		FrontDomains:      []string{"www.cdn77.com", "www.phpmyadmin.net"},
		ICEAddresses: []string{
			"stun:stun.antisip.com:3478", "stun:stun.epygi.com:3478",
			"stun:stun.uls.co.za:3478", "stun:stun.voipgate.com:3478",
			"stun:stun.mixvoip.com:3478", "stun:stun.nextcloud.com:3478",
			"stun:stun.bethesda.net:3478", "stun:stun.nextcloud.com:443",
		},
		Max:                1,
		KeepLocalAddresses: false,
		UTLSClientID:       "hellorandomizedalpn",
		Log:                &logger,
	}
}

// UnfrontedOptions returns the same public defaults with every fronting
// preset cleared: it selects the direct HTTPS rendezvous against BrokerURL.
// That is a different, weaker configuration class from the fronted default
// and must be evaluated and documented separately (E4.4); the TLS SNI and
// DNS of the broker become visible. The bridge fingerprint pin and silent
// logger stay mandatory.
func UnfrontedOptions() snowflake_client.ClientConfig {
	cfg := DefaultOptions()
	cfg.FrontDomains = nil
	cfg.FrontDomain = ""
	return cfg
}

func Dial(cfg snowflake_client.ClientConfig) (net.Conn, error) {
	return DialContext(context.Background(), cfg)
}

// DialContext returns a bridge-pinned byte stream. Gonion still authenticates
// Tor CERTS against this pin; broker routing alone is not authentication.
// Cancellation bounds the wait and closes late connections. The upstream API
// has no context/Transport.Close, so in-flight NAT probes may finish afterward.
func DialContext(ctx context.Context, cfg snowflake_client.ClientConfig) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := hex.DecodeString(cfg.BridgeFingerprint)
	if err != nil || len(id) != 20 || [20]byte(id) == [20]byte{} {
		return nil, fmt.Errorf("snowflake: a nonzero 40-digit bridge fingerprint is required")
	}
	conn, err := dialContext(ctx, func() (net.Conn, error) {
		transport, err := snowflake_client.NewSnowflakeClient(cfg)
		if err != nil {
			return nil, err
		}
		return transport.Dial()
	})
	if err != nil {
		return nil, err
	}
	return &pinnedConn{Conn: conn, identity: [20]byte(id)}, nil
}

type pinnedConn struct {
	net.Conn
	identity  [20]byte
	closeOnce sync.Once
	closeErr  error
}

func (c *pinnedConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func (c *pinnedConn) ExpectedRelayIdentity() [20]byte { return c.identity }

func dialContext(ctx context.Context, dial func() (net.Conn, error)) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result)
	go func() {
		conn, err := dial()
		if err != nil && conn != nil {
			_ = conn.Close()
			conn = nil
		}
		if err == nil && conn == nil {
			err = fmt.Errorf("snowflake: dial returned nil connection")
		}
		select {
		case done <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		if ctx.Err() != nil {
			if r.conn != nil {
				_ = r.conn.Close()
			}
			return nil, ctx.Err()
		}
		return r.conn, r.err
	}
}
