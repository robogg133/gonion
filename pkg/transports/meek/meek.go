// Package meek provides a client connection through the meek pluggable
// transport (https://gitlab.torproject.org/tpo/anti-censorship/pluggable-
// transports/meek). The protocol logic mirrors the upstream meek-client,
// which cannot be imported directly (package main).
package meek

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// A session ID is a randomly generated string that identifies a
	// long-lived session. We split a TCP stream across multiple HTTP
	// requests, and those with the same session ID belong to the same
	// stream.
	sessionIDLength = 8
	// The size of the largest chunk of data we will forward in a request,
	// and the maximum size of a body we are willing to handle in a reply.
	maxPayloadLength = 0x10000
	// We must poll the server to see if it has anything to send; there is
	// no way for the server to push data back to us until we send an HTTP
	// request. When a timer expires, we send a request even if it has an
	// empty body. The interval starts at this value and then grows.
	initPollInterval = 100 * time.Millisecond
	// Maximum polling interval.
	maxPollInterval = 5 * time.Second
	// Geometric increase in the polling interval each time we fail to read
	// data.
	pollIntervalMultiplier = 1.5
	// Try an HTTP roundtrip at most this many times.
	maxTries = 10
	// Wait this long between retries.
	retryDelay = 30 * time.Second
)

// We use this RoundTripper to make all our requests. We use the defaults,
// except we take control of the Proxy setting (notably, disabling the default
// ProxyFromEnvironment). The cloned transport keeps DefaultTransport's
// net.Dialer.DialContext, so an HTTP request context also cancels TCP and TLS
// establishment; the bridge must be reached directly, never through an
// environment-configured proxy.
var httpRoundTripper = func() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return tr
}()

// RequestInfo encapsulates all the configuration used for a request-response
// roundtrip.
type RequestInfo struct {
	// What to put in the X-Session-ID header.
	SessionID string
	// The URL to request.
	URL *url.URL
	// The Host header to put in the HTTP request (optional and may be
	// different from the host name in URL).
	Host string
	// The RoundTripper to use to send requests.
	RoundTripper http.RoundTripper
	// transport is the per-connection clone behind RoundTripper. It is kept
	// so a failed dial or Close can release idle connections that the
	// transport established but did not use.
	transport *http.Transport
}

// Dial connects to a meek bridge. bridgeURL is the endpoint URL (the url=
// argument of the Bridge line); front optionally is the front domain (the
// front= argument): when given, the domain in the URL is replaced by the
// front domain for the purpose of the DNS lookup, TCP connection, and TLS
// SNI, but the HTTP Host header in the request remains the one in bridgeURL.
//
// Like upstream, the bridge address on the Bridge line is ignored.
//
// Dial retains the historical behavior of returning immediately without
// touching the network; the first HTTP request happens when the returned
// connection is first read or written. Use DialContext to bound an initial
// roundtrip with a context.
func Dial(bridgeURL, front string) (net.Conn, error) {
	info, err := newRequestInfo(bridgeURL, front)
	if err != nil {
		return nil, err
	}
	return start(info), nil
}

// DialContext connects to a meek bridge like Dial, but the initial HTTP
// roundtrip is bounded by ctx. Pre-canceled contexts fail without network
// access, and canceling during the roundtrip closes the underlying TCP/TLS
// connection. After a successful return the connection owns its lifetime:
// canceling ctx does not close it. Proxy settings from the environment are
// never inherited.
func DialContext(ctx context.Context, bridgeURL, front string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := newRequestInfo(bridgeURL, front)
	if err != nil {
		return nil, err
	}
	if err := handshake(ctx, info); err != nil {
		info.transport.CloseIdleConnections()
		return nil, err
	}
	// Cancellation that raced with a successful roundtrip still wins; a
	// connection returned from here is independent of the caller's context.
	if err := ctx.Err(); err != nil {
		info.transport.CloseIdleConnections()
		return nil, err
	}
	return start(info), nil
}

func newRequestInfo(bridgeURL, front string) (*RequestInfo, error) {
	u, err := url.Parse(bridgeURL)
	if err != nil {
		return nil, fmt.Errorf("meek: parse url failed: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("meek: unsupported scheme %q", u.Scheme)
	}

	// Isolate each stream's HTTP pool and make it releasable on failure or
	// Close. Clone preserves the disabled environment proxy and the
	// context-aware net.Dialer.
	tr := httpRoundTripper.Clone()
	info := &RequestInfo{
		SessionID:    genSessionID(),
		URL:          u,
		RoundTripper: tr,
		transport:    tr,
	}
	if front != "" {
		info.Host = info.URL.Host
		info.URL.Host = front
	}
	return info, nil
}

// start runs the meek engine against one end of an in-memory duplex pipe and
// returns the caller's end. The pipe is synchronous, so callers should read
// and write concurrently (as gonion's Conn read/write loops do). The returned
// connection closes its own request context on Close, aborting an in-flight
// HTTP roundtrip.
func start(info *RequestInfo) net.Conn {
	inner, outer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		_ = copyLoop(ctx, inner, info)
		_ = inner.Close()
	}()
	return &meekConn{Conn: outer, cancel: cancel, transport: info.transport}
}

type meekConn struct {
	net.Conn
	cancel    context.CancelFunc
	transport *http.Transport
	once      sync.Once
}

func (c *meekConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		if c.transport != nil {
			c.transport.CloseIdleConnections()
		}
	})
	return c.Conn.Close()
}

// handshake performs one empty roundtrip so DialContext can report
// cancellation and establish the TCP/TLS connection. A session ID is fresh,
// so the server cannot have stream data for it; the probe response is closed
// without being forwarded.
func handshake(ctx context.Context, info *RequestInfo) error {
	resp, err := roundTripRetries(ctx, info.RoundTripper, func() (*http.Request, error) {
		return makeRequest(ctx, nil, info)
	}, maxTries)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	_ = resp.Body.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// Make an http.Request from the payload data in buf and the request metadata
// in info.
func makeRequest(ctx context.Context, buf []byte, info *RequestInfo) (*http.Request, error) {
	var body io.Reader
	if len(buf) > 0 {
		// Leave body == nil when buf is empty. A nil body is an
		// explicit signal that the body is empty. An empty
		// *bytes.Reader or the magic value http.NoBody are supposed to
		// be equivalent ways to signal an empty body, but in Go 1.8 the
		// HTTP/2 code only understands nil. Not leaving body == nil
		// causes the Content-Length header to be omitted from HTTP/2
		// requests, which in some cases can cause the server to return
		// a 411 "Length Required" error. See
		// https://bugs.torproject.org/22865.
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", info.URL.String(), body)
	if err != nil {
		return nil, err
	}
	// Prevent Content-Type sniffing by net/http and middleboxes.
	req.Header.Set("Content-Type", "application/octet-stream")
	if info.Host != "" {
		req.Host = info.Host
	}
	req.Header.Set("X-Session-Id", info.SessionID)
	return req, nil
}

// Do a roundtrip, trying at most limit times if there is an HTTP status other
// than 200. In case all tries result in error, returns the last error seen.
// Cancellation interrupts both the roundtrip and the delay between retries.
//
// Retrying the request immediately is a bit bogus, because we don't know if the
// remote server received our bytes or not, so we may be sending duplicates,
// which will cause the connection to die. The alternative, though, is to just
// kill the connection immediately. A better solution would be a system of
// acknowledgements so we know what to resend after an error.
func roundTripRetries(ctx context.Context, rt http.RoundTripper, makeReq func() (*http.Request, error), limit int) (*http.Response, error) {
	var resp *http.Response
	var err error
again:
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	limit--
	resp, err = func() (*http.Response, error) {
		req, err := makeReq()
		if err != nil {
			return nil, err
		}
		return rt.RoundTrip(req)
	}()
	// Retry only if the HTTP roundtrip completed without error, but
	// returned a status other than 200. Other kinds of errors and success
	// with 200 always return immediately.
	if err == nil && resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		err = fmt.Errorf("status code was %d, not %d", resp.StatusCode, http.StatusOK)
		if limit > 0 {
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			goto again
		}
	}
	return resp, err
}

// Send the data in buf to the remote URL, wait for a reply, and feed the reply
// body back into conn.
func sendRecv(ctx context.Context, buf []byte, conn net.Conn, info *RequestInfo) (int64, error) {
	resp, err := roundTripRetries(ctx, info.RoundTripper, func() (*http.Request, error) {
		return makeRequest(ctx, buf, info)
	}, maxTries)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return io.Copy(conn, io.LimitReader(resp.Body, maxPayloadLength))
}

// Repeatedly read from conn, issue HTTP requests, and write the responses back
// to conn.
func copyLoop(ctx context.Context, conn net.Conn, info *RequestInfo) error {
	var interval time.Duration

	ch := make(chan []byte)
	done := make(chan struct{})
	defer close(done)

	// Read from the Conn and send byte slices on the channel. Select on done
	// so this goroutine cannot outlive copyLoop when a request fails while a
	// read result is waiting to be consumed.
	go func() {
		defer close(ch)
		var buf [maxPayloadLength]byte
		r := bufio.NewReader(conn)
		for {
			n, err := r.Read(buf[:])
			b := make([]byte, n)
			copy(b, buf[:n])
			select {
			case ch <- b:
			case <-done:
				return
			}
			if err != nil {
				break
			}
		}
	}()

	interval = initPollInterval
loop:
	for {
		var buf []byte
		var ok bool

		select {
		case buf, ok = <-ch:
			if !ok {
				break loop
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
			buf = nil
		}

		nw, err := sendRecv(ctx, buf, conn, info)
		if err != nil {
			return err
		}

		if nw > 0 || len(buf) > 0 {
			// If we sent or received anything, poll again
			// immediately.
			interval = 0
		} else if interval == 0 {
			// The first time we don't send or receive anything,
			// wait a while.
			interval = initPollInterval
		} else {
			// After that, wait a little longer.
			interval = time.Duration(float64(interval) * pollIntervalMultiplier)
		}
		if interval > maxPollInterval {
			interval = maxPollInterval
		}
	}

	return nil
}

func genSessionID() string {
	buf := make([]byte, sessionIDLength)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err.Error())
	}
	return strings.TrimRight(base64.StdEncoding.EncodeToString(buf), "=")
}
