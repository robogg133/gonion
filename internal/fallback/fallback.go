package fallback

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/robogg133/gonion/internal/shared"
)

type FallBackDialer struct {
	list []shared.FallbackDir
}

func New(list []shared.FallbackDir) *FallBackDialer {
	return &FallBackDialer{
		list: append([]shared.FallbackDir(nil), list...),
	}
}

// Dial creates a new fallbackdialer with default fallback dirs list and dial
func Dial(ipv6Enabled bool) (net.Conn, error) {
	return New(shared.Fallbacks).Dial(ipv6Enabled)
}

func (fb *FallBackDialer) Dial(tryipv6 bool) (net.Conn, error) {
	return fb.DialContext(context.Background(), tryipv6)
}

// DialContext carries the selected fallback's RSA identity into the OR
// handshake. Returning only its address would lose the identity pin.
func (fb *FallBackDialer) DialContext(ctx context.Context, tryipv6 bool) (net.Conn, error) {
	var failures []error
	for _, v := range fb.list {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(v.Fingerprint)
		if err != nil || len(raw) != 20 || [20]byte(raw) == [20]byte{} || net.ParseIP(v.IPv4).To4() == nil || v.ORPort == 0 {
			failures = append(failures, fmt.Errorf("fallback: invalid identity or IPv4 endpoint"))
			continue
		}
		addresses := []string{net.JoinHostPort(v.IPv4, strconv.Itoa(int(v.ORPort)))}
		if tryipv6 && v.IPv6 != "" && v.IPv6Port != 0 {
			if ip := net.ParseIP(v.IPv6); ip != nil && ip.To4() == nil {
				addresses = append(addresses, net.JoinHostPort(v.IPv6, strconv.Itoa(int(v.IPv6Port))))
			}
		}
		for _, addr := range addresses {
			conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
			if err == nil {
				return &pinnedConn{Conn: conn, identity: [20]byte(raw)}, nil
			}
			failures = append(failures, err)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
	}
	if len(failures) == 0 {
		return nil, fmt.Errorf("fallback: no directory relays configured")
	}
	return nil, errors.Join(failures...)
}

type pinnedConn struct {
	net.Conn
	identity [20]byte
}

func (c *pinnedConn) ExpectedRelayIdentity() [20]byte { return c.identity }
