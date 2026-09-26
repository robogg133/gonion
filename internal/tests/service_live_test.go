package tests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/embed"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

// This publishes only a newly generated, ephemeral identity. No application
// identity, private key or descriptor is written to disk or logged. Public
// network use is opt-in; an optional C Tor process is a test peer, never a
// Gonion runtime dependency or a substitute for Gonion's onion implementation.
func TestEmbedListenOnion(t *testing.T) {
	if os.Getenv("GONION_TEST_SERVICE") != "1" {
		t.Skip("set GONION_TEST_SERVICE=1 to publish an ephemeral onion service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	log := zerolog.New(os.Stderr).Level(zerolog.DebugLevel).With().Timestamp().Logger()
	ctx = log.WithContext(ctx)
	var reference <-chan referenceResult
	if os.Getenv("GONION_TEST_REFERENCE_TOR") == "1" {
		reference = startReferenceTor(t, ctx)
	}
	opts := embed.DefaultOptions()
	opts.ORDialer = func(ctx context.Context) (net.Conn, error) {
		return fallback.New(shared.Fallbacks).DialContext(ctx, true)
	}
	opts.GuardDialer = func(ctx context.Context, r *common.RouterStatus) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(r.Ipv4Addr, strconv.Itoa(int(r.ORPort))))
	}
	client, err := embed.New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identity)
	var revision atomic.Uint64 // Safe only because this identity is fresh/ephemeral.
	initCtx, finishInit := context.WithTimeout(ctx, 8*time.Minute)
	listener, err := client.Listen(initCtx, embed.ServiceOptions{Identity: identity, Port: 80, NextRevision: func(context.Context, [32]byte) (uint64, error) { return revision.Add(1), nil }})
	finishInit()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Shutdown()
	t.Log("both descriptor periods published; initialization context cancelled")
	dialers := []struct {
		name string
		dial func(context.Context, string, string) (net.Conn, error)
	}{{"Gonion", client.DialContext}}
	if reference != nil {
		select {
		case peer := <-reference:
			if peer.err != nil {
				t.Fatal(peer.err)
			}
			dialers = append(dialers, struct {
				name string
				dial func(context.Context, string, string) (net.Conn, error)
			}{"C Tor", peer.dialer.DialContext})
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for i, dialer := range dialers {
		t.Logf("dialing ephemeral service with %s", dialer.name)
		conn, err := dialer.dial(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("%s Dial: %v (maintenance: %v)", dialer.name, err, listener.Err())
		}
		defer conn.Close()
		server, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		last := i == len(dialers)-1
		if last {
			_ = listener.Close()
			if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept after Close: %v", err)
			}
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
		_ = server.SetDeadline(time.Now().Add(2 * time.Minute))
		payload := make([]byte, 1<<20) // Exceeds both stream and circuit windows.
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		echoDone := make(chan error, 1)
		go func() {
			received := make([]byte, len(payload))
			_, err := io.ReadFull(server, received)
			if err == nil && !bytes.Equal(received, payload) {
				err = errors.New("service received corrupted application data")
			}
			if err == nil {
				_, err = server.Write(received)
			}
			echoDone <- err
		}()
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("%s upload: %v", dialer.name, err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
			t.Fatalf("%s echo corrupted/truncated: %v", dialer.name, err)
		}
		if err := <-echoDone; err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: verified 1 MiB in each direction; listener closed=%v", dialer.name, last)
		if last {
			_ = client.Close()
			_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := server.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Client.Close did not terminate accepted stream: %v", err)
			}
		}
		_ = conn.Close()
		_ = server.Close()
	}
}

type referenceResult struct {
	dialer proxy.ContextDialer
	err    error
}

func startReferenceTor(t *testing.T, parent context.Context) <-chan referenceResult {
	t.Helper()
	binary, err := exec.LookPath("tor")
	if err != nil {
		t.Fatal("GONION_TEST_REFERENCE_TOR requires a C Tor executable on PATH")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "torrc")
	if err := os.WriteFile(config, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, binary, "-f", config, "--DataDirectory", dir, "--SocksPort", "auto", "--ControlPort", "0", "--ClientOnly", "1", "--AvoidDiskWrites", "1", "--RunAsDaemon", "0", "--Log", "notice stdout")
	cmd.WaitDelay = 3 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	result := make(chan referenceResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stdout)
		port, ready := "", false
		for scanner.Scan() {
			line := scanner.Text()
			const marker = "Socks listener listening on port "
			if i := strings.Index(line, marker); i >= 0 {
				port = strings.TrimSuffix(strings.TrimSpace(line[i+len(marker):]), ".")
			}
			if strings.Contains(line, "Bootstrapped") || strings.Contains(line, "[warn]") {
				t.Logf("reference Tor: %s", line)
			}
			if !ready && strings.Contains(line, "Bootstrapped 100%") {
				n, err := strconv.ParseUint(port, 10, 16)
				if err != nil || n == 0 {
					result <- referenceResult{err: fmt.Errorf("reference Tor did not report a SOCKS port")}
					return
				}
				dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", port), nil, &net.Dialer{})
				if err != nil {
					result <- referenceResult{err: err}
					return
				}
				result <- referenceResult{dialer: dialer.(proxy.ContextDialer)}
				ready = true
			}
		}
		if !ready {
			result <- referenceResult{err: fmt.Errorf("reference Tor exited before bootstrap: %v", scanner.Err())}
		}
	}()
	t.Cleanup(func() { cancel(); _ = cmd.Wait(); <-done })
	return result
}
