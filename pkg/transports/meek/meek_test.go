package meek

import (
	"bytes"
	"io"
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
	var host, sessionID string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		sessionID = r.Header.Get("X-Session-Id")
		close(done)
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
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("no request arrived")
	}
	// The Host header must carry the bridge URL host, while the request
	// itself went to the front address.
	if host != "bridge.example.test" {
		t.Fatalf("Host header = %q, want %q", host, "bridge.example.test")
	}
	if sessionID == "" {
		t.Fatal("missing X-Session-Id")
	}
}
