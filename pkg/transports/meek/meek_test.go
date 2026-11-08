package meek

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// minimal meek-server: per-session cumulative buffer; each POST appends its
// body and replies with everything not yet delivered.
func newMeekTestServer() *httptest.Server {
	var mu sync.Mutex
	bufs := map[string]*bytes.Buffer{}
	off := map[string]int{}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sid := r.Header.Get("X-Session-Id")
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		b := bufs[sid]
		if b == nil {
			b = &bytes.Buffer{}
			bufs[sid] = b
		}
		b.Write(body)
		o := off[sid]
		out := make([]byte, b.Len()-o)
		copy(out, b.Bytes()[o:])
		off[sid] = b.Len()
		mu.Unlock()
		w.Write(out)
	}))
}

func TestDialLocalEcho(t *testing.T) {
	srv := newMeekTestServer()
	defer srv.Close()

	conn, err := Dial(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	msg := []byte("gonion meek roundtrip")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q != %q", got, msg)
	}
}

func TestDialFrontSetsHostHeader(t *testing.T) {
	type request struct{ host, sessionID string }
	requests := make(chan request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- request{r.Host, r.Header.Get("X-Session-Id")}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// front = the test server's actual address (so it routes); bridgeURL
	// host = a fake domain that must appear in the Host header.
	front := srv.Listener.Addr().String()
	conn, err := Dial("http://bridge.example.test/", front)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case req := <-requests:
		// The Host header must carry the bridge URL host, while the request
		// itself went to the front address.
		if req.host != "bridge.example.test" {
			t.Fatalf("Host header = %q, want %q", req.host, "bridge.example.test")
		}
		if req.sessionID == "" {
			t.Fatal("missing X-Session-Id")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no request arrived")
	}
}

func TestDialContextPreCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := DialContext(ctx, "http://127.0.0.1:1/", "")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("pre-canceled dial returned a connection")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled dial error = %v, want context.Canceled", err)
	}
}

// TestDialContextCancelsHangingHandshake accepts the TCP connection but never
// sends an HTTP response, then cancels the context. DialContext must return
// promptly and the underlying connection must be closed.
func TestDialContextCancelsHangingHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := DialContext(ctx, "http://"+ln.Addr().String()+"/", "")
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not reach the test listener")
	}
	defer serverConn.Close()

	// Wait until the POST request headers are on the wire, so cancellation
	// happens while the transport is waiting for the (never sent) response
	// headers rather than during a dial race.
	_ = serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	request := make([]byte, 0, 1024)
	buf := make([]byte, 256)
	for !bytes.Contains(request, []byte("\r\n\r\n")) {
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Fatalf("reading request headers: %v", err)
		}
		request = append(request, buf[:n]...)
	}
	_ = serverConn.SetReadDeadline(time.Time{})

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled handshake error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialContext did not return after cancellation")
	}

	// The canceled roundtrip must close the connection instead of leaving it
	// in the transport pool or running until the server responds.
	for {
		_ = serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := serverConn.Read(buf)
		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("canceled dial left the TCP connection open")
		}
		break
	}
}

// TestDialContextReturnedConnectionIndependent verifies that canceling the
// context after a successful dial does not affect the returned connection.
func TestDialContextReturnedConnectionIndependent(t *testing.T) {
	srv := newMeekTestServer()
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := DialContext(ctx, srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cancel()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	msg := []byte("meek context independence")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q != %q", got, msg)
	}
}

func TestTransportContextAndProxyConfiguration(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	if httpRoundTripper.Proxy != nil {
		t.Fatal("meek transport inherits environment proxy settings")
	}
	if httpRoundTripper.DialContext == nil {
		t.Fatal("meek transport has no context-aware TCP dialer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := httpRoundTripper.DialContext(ctx, "tcp", "127.0.0.1:1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("TCP dialer did not observe cancellation: %v", err)
	}
}
