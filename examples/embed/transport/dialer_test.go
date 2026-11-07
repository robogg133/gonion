package main

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/robogg133/gonion/examples/embed/transport/internal/bootstrap"
)

func TestInvalidTransportOptions(t *testing.T) {
	for _, fingerprint := range []string{"", "0000000000000000000000000000000000000000", "Z123456789ABCDEF0123456789ABCDEF01234567"} {
		t.Run(fingerprint, func(t *testing.T) {
			if _, err := bootstrap.Options(fingerprint, filepath.Join(t.TempDir(), "guards.json"), nil); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestLegacyDialerLateConnectionClosed(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := bootstrap.LegacyDialer(func() (net.Conn, error) {
			close(started)
			<-release
			return client, nil
		})(ctx)
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not return while Dial was blocked")
	}
	// Release Dial only after the caller has returned, forcing late cleanup.
	release <- struct{}{}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("late connection not closed: %v", err)
	}
}

func TestLegacyDialerReturnedConnectionSurvivesCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := bootstrap.LegacyDialer(func() (net.Conn, error) { return client, nil })(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := server.Write([]byte{42}); done <- err }()
	var buf [1]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil || buf[0] != 42 {
		t.Fatalf("returned connection affected by cancellation: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLegacyDialerError(t *testing.T) {
	want := errors.New("transport failed")
	conn, err := bootstrap.LegacyDialer(func() (net.Conn, error) { return nil, want })(context.Background())
	if conn != nil || err != want {
		t.Fatalf("got %v, %v", conn, err)
	}
}
