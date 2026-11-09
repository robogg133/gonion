// Package obfs4 adapts the pinned upstream obfs4 client transport
// (gitlab.com/yawning/obfs4.git, pseudo-version
// v0.0.0-20231012084234-c3e2d44b1033, 2023-10-12) to a context-aware
// net.Conn dialer for Gonion bridge configuration.
//
// Third-party exposure for a controlled or public obfs4 bridge is limited to
// direct TCP (and hostname resolution, when addr is not a literal IP) to the
// bridge endpoint itself: no broker, no DNS beyond that endpoint, no
// ICE/STUN/TURN, and no WebRTC. That is materially less exposure than
// Snowflake; see pkg/transports/snowflake for its separate inventory. The
// bridge line's leading <FINGERPRINT> is the Tor RSA relay identity and is
// enforced here as a connection pin; the cert= argument is the obfs4 ntor
// transport key, and iat-mode selects the idle-packet behaviour.
//
// Evidence scope (E4.4): the package tests run a *controlled* local obfs4
// bridge using the upstream server transport, so the handshake, certificate
// authentication, identity pinning, and cancellation behavior are validated
// without any public relay. They are not interoperability proof against a
// specific third-party bridge, and nothing here is evidence of censorship
// a live public-bridge handshake passed on 2026-11-08. The former root-side
// incompatibility (upstream obfs4Conn implements SetDeadline as ENOTSUP while
// the core link handshake required socket deadlines) is resolved: the link
// handshake now bounds itself with context and tolerates ENOTSUP deadlines.
// A live public obfs4 bootstrap remains the outstanding evidence step.
package obfs4

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

// Dial connects to an obfs4 bridge with a background context. See
// DialContext for the meaning and mandatory validation of each argument.
func Dial(addr, nodeID, cert, iatMode string) (net.Conn, error) {
	return DialContext(context.Background(), addr, nodeID, cert, iatMode)
}

// DialContext cancels both TCP establishment and the obfs4 handshake. After a
// successful return, ctx no longer controls the returned connection's lifetime.
//
// nodeID is the bridge line's Tor RSA fingerprint (40 hex digits). It is
// mandatory, nonzero, and the returned connection carries it as
// ExpectedRelayIdentity so gonion's CERTS verification must match this actual
// relay identity — the transport certificate alone never substitutes for it
// (E4.1). cert is the base64 obfs4 ntor transport certificate and iatMode is
// the idle-packet mode ("0", "1", or "2"); both are validated by the upstream
// factory before any connection is attempted.
//
// Migration (security-required): earlier versions accepted an empty or
// arbitrary node-id string because the upstream new-format parser derives the
// ntor node ID from cert= alone. Callers must now supply the real 20-byte RSA
// fingerprint, exactly as a pinned embed.BridgeOptions.Identity requires.
func DialContext(ctx context.Context, addr, nodeID, cert, iatMode string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := parseRelayIdentity(nodeID)
	if err != nil {
		return nil, err
	}
	transport := new(obfs4.Transport)

	fac, err := transport.ClientFactory("")
	if err != nil {
		return nil, err
	}

	args := &pt.Args{}

	args.Add("cert", cert)
	args.Add("iat-mode", iatMode)
	args.Add("node-id", nodeID)

	obfsArgs, err := fac.ParseArgs(args)
	if err != nil {
		return nil, err
	}

	var raw net.Conn
	var stop func() bool
	conn, err := fac.Dial("tcp", addr, func(network, address string) (net.Conn, error) {
		var dialErr error
		raw, dialErr = (&net.Dialer{}).DialContext(ctx, network, address)
		if dialErr == nil {
			stop = context.AfterFunc(ctx, func() { _ = raw.Close() })
		}
		return raw, dialErr
	}, obfsArgs)
	if stop != nil {
		stop()
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, err
	}
	return &pinnedConn{Conn: conn, identity: id}, nil
}

// parseRelayIdentity enforces the actual Tor RSA identity, not a transport
// key: exactly 40 hex digits and nonzero.
func parseRelayIdentity(nodeID string) ([20]byte, error) {
	var zero [20]byte
	id, err := hex.DecodeString(strings.ToUpper(nodeID))
	if err != nil || len(id) != 20 || [20]byte(id) == zero {
		return zero, fmt.Errorf("obfs4: a nonzero 40-digit RSA fingerprint is required")
	}
	return [20]byte(id), nil
}

// pinnedConn carries the expected Tor RSA identity so the link handshake
// must match it against the authenticated CERTS key. Close is idempotent.
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
