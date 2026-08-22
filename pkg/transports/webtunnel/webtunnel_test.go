package webtunnel

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDialLocalEcho(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
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
		addrs, err := lookup(host, "443")
		if err == nil || len(addrs) != 0 {
			t.Errorf("lookup(%s) = %v, want filtered", host, addrs)
		}
	}
}
