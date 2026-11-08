package webtunnel

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// upgradeEcho answers a WebSocket-upgrade request with 101 and echoes the
// hijacked connection afterwards.
func upgradeEcho(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/wtpath" || strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		http.NotFound(w, r)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	netConn, brw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer netConn.Close()
	resp := "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
	if _, err := netConn.Write([]byte(resp)); err != nil {
		return
	}
	io.Copy(netConn, brw.Reader)
}

func TestDialLocalEcho(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(upgradeEcho))
	srv.StartTLS()
	defer srv.Close()

	leafHash := sha256.Sum256(srv.Certificate().Raw)
	pin := base64.StdEncoding.EncodeToString(leafHash[:])

	conn, err := Dial(srv.URL+"/wtpath", srv.Listener.Addr().String(), "", pin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	msg := []byte("gonion webtunnel roundtrip")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: %q != %q", got, msg)
	}
}

func TestLookupFiltersPrivate(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "192.168.1.2"} {
		addrs, err := lookup(context.Background(), host, "443")
		if err == nil || len(addrs) != 0 {
			t.Errorf("lookup(%s) = %v, want filtered", host, addrs)
		}
	}
}

func TestDialContextCancelBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := DialContext(ctx, "https://example.invalid/wtpath", "", "", "")
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, %v; want nil, context.Canceled", conn, err)
	}
}

// silentListener accepts one connection and never answers on it.
func silentListener(t *testing.T) (addr string, accepted chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted = make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	return ln.Addr().String(), accepted
}

// readEOF reports whether the peer closed its side within the deadline.
func readEOF(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("%s: peer did not close its connection: %v", what, err)
	}
}

func dialAsync(ctx context.Context, bridgeURL, addr string) chan error {
	res := make(chan error, 1)
	go func() {
		conn, err := DialContext(ctx, bridgeURL, addr, "", "")
		if err == nil {
			_ = conn.Close()
			err = errors.New("webtunnel: canceled dial returned a connection")
		}
		res <- err
	}()
	return res
}

func TestDialContextCancelsDuringUpgrade(t *testing.T) {
	addr, accepted := silentListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := dialAsync(ctx, "http://"+addr+"/wtpath", addr)

	serverConn := <-accepted
	defer serverConn.Close()
	cancel()

	select {
	case err := <-res:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v; want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DialContext ignored cancellation during the upgrade")
	}
	readEOF(t, serverConn, "upgrade")
}

func TestDialContextCancelsDuringTLSHandshake(t *testing.T) {
	addr, accepted := silentListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := dialAsync(ctx, "https://"+addr+"/wtpath", addr)

	serverConn := <-accepted
	defer serverConn.Close()
	cancel()

	select {
	case err := <-res:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v; want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DialContext ignored cancellation during the TLS handshake")
	}
	readEOF(t, serverConn, "TLS handshake")
}

func TestDialContextDeadlineDuringUpgrade(t *testing.T) {
	addr, accepted := silentListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := dialAsync(ctx, "http://"+addr+"/wtpath", addr)

	serverConn := <-accepted
	defer serverConn.Close()

	select {
	case err := <-res:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v; want context.DeadlineExceeded", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DialContext ignored its deadline during the upgrade")
	}
	readEOF(t, serverConn, "deadline")
}

func TestDialContextFailedUpgradeClosesConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	closed := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
			closed <- err
			return
		}
		if _, err := conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")); err != nil {
			closed <- err
			return
		}
		_, err = io.Copy(io.Discard, conn) // returns nil only at EOF
		closed <- err
	}()

	conn, err := Dial("http://"+addr+"/wtpath", addr, "", "")
	if conn != nil || err == nil {
		t.Fatalf("non-101 upgrade accepted: conn=%v err=%v", conn, err)
	}
	select {
	case serr := <-closed:
		if serr != nil {
			t.Fatalf("server drain failed: %v", serr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("failed dial left the connection open")
	}
}

func TestDialContextSuccessTransfersOwnership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(upgradeEcho))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	conn, err := DialContext(ctx, srv.URL+"/wtpath", srv.Listener.Addr().String(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	msg := []byte("post-cancel roundtrip")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: %q != %q", got, msg)
	}
}
