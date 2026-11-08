package obfs4

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/yawning/obfs4.git/common/drbg"
	"gitlab.com/yawning/obfs4.git/common/ntor"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

func TestDialContextCancellationBeforeIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := DialContext(ctx, "", "", "", "")
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled transport dial: %v", err)
	}
}

// TestDialContextRejectsInvalidArguments proves every argument class fails
// closed before any socket is opened: the RSA pin is mandatory (E4.1/E4.4)
// and the upstream factory validates cert= and iat-mode before dialing.
func TestDialContextRejectsInvalidArguments(t *testing.T) {
	for _, fp := range []string{"", "xyz", strings.Repeat("0", 40), strings.Repeat("ab", 19), strings.Repeat("ab", 21)} {
		conn, err := DialContext(context.Background(), "127.0.0.1:1", fp, "KciXEUlkxmOHsVFLh6s3fAEWO7p0GHt6jhhTj/XaWM8/VmCYqbzPmRM+Q4PA1AcJ8JyWBA", "0")
		if conn != nil || err == nil || !strings.Contains(err.Error(), "RSA fingerprint") {
			t.Fatalf("invalid fingerprint %q accepted: %v", fp, err)
		}
	}
	goodFP := strings.Repeat("AB", 20)
	for _, cert := range []string{"not-a-cert", ""} {
		conn, err := DialContext(context.Background(), "127.0.0.1:1", goodFP, cert, "0")
		if conn != nil || err == nil {
			t.Fatalf("invalid transport certificate accepted: %v", err)
		}
	}
	conn, err := DialContext(context.Background(), "127.0.0.1:1", goodFP, "KciXEUlkxmOHsVFLh6s3fAEWO7p0GHt6jhhTj/XaWM8/VmCYqbzPmRM+Q4PA1AcJ8JyWBA", "9")
	if conn != nil || err == nil || !strings.Contains(err.Error(), "iat-mode") {
		t.Fatalf("invalid iat-mode accepted: %v", err)
	}
}

// controlledBridge runs the upstream obfs4 *server* transport locally,
// producing deterministic E4.4 evidence for the handshake, certificate
// authentication, identity pinning, and cancellation without any public
// relay. It is not interoperability evidence for a specific third-party
// bridge.
type controlledBridge struct {
	addr     string
	cert     string // client-side cert= argument of this bridge
	accepted chan struct{}
	stall    bool // accept but never complete the server handshake
}

func newControlledBridge(t *testing.T, echo, stall bool) *controlledBridge {
	t.Helper()
	transport := new(obfs4.Transport)
	rawID := make([]byte, ntor.NodeIDLength)
	if _, err := rand.Read(rawID); err != nil {
		t.Fatal(err)
	}
	nodeID, err := ntor.NewNodeID(rawID)
	if err != nil {
		t.Fatal(err)
	}
	keypair, err := ntor.NewKeypair(false)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := drbg.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	args := &pt.Args{}
	args.Add("node-id", nodeID.Hex())
	args.Add("private-key", keypair.Private().Hex())
	args.Add("drbg-seed", seed.Hex())
	args.Add("iat-mode", "0")
	sf, err := transport.ServerFactory(t.TempDir(), args)
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := sf.Args().Get("cert")
	if !ok {
		t.Fatal("server args missing cert")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var mu sync.Mutex
	var raws []net.Conn
	var live []net.Conn
	accepted := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			raws = append(raws, conn)
			mu.Unlock()
			select {
			case accepted <- struct{}{}:
			default:
			}
			if stall {
				continue
			}
			go func() {
				wrapped, err := sf.WrapConn(conn)
				if err != nil {
					_ = conn.Close()
					return
				}
				mu.Lock()
				live = append(live, wrapped)
				mu.Unlock()
				if echo {
					_, _ = io.Copy(wrapped, wrapped)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range live {
			_ = c.Close()
		}
		for _, c := range raws {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return &controlledBridge{addr: listener.Addr().String(), cert: cert, accepted: accepted, stall: stall}
}

// TestControlledObfs4PinnedBridgeFlow runs the full client handshake against
// a controlled local obfs4 bridge and proves the returned connection carries
// the mandatory RSA identity pin that embed's CERTS verification enforces.
func TestControlledObfs4PinnedBridgeFlow(t *testing.T) {
	t.Parallel()
	br := newControlledBridge(t, true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pin := strings.Repeat("CD", 20)
	conn, err := DialContext(ctx, br.addr, pin, br.cert, "0")
	if err != nil {
		t.Fatalf("controlled handshake: %v", err)
	}
	defer conn.Close()
	pinned, ok := conn.(interface{ ExpectedRelayIdentity() [20]byte })
	if !ok {
		t.Fatal("pinned identity metadata missing")
	}
	raw, err := hex.DecodeString(pin)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.ExpectedRelayIdentity() != [20]byte(raw) {
		t.Fatal("connection carries a different relay identity")
	}
	if _, err := conn.Write([]byte("obfs4 payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 13)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != "obfs4 payload" {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

// TestControlledObfs4RejectsForeignCertificate proves certificate binding is
// enforced by the ntor handshake: a valid-looking bridge line for a
// *different* key pair cannot complete against this bridge.
func TestControlledObfs4RejectsForeignCertificate(t *testing.T) {
	t.Parallel()
	br := newControlledBridge(t, true, false)
	other := newControlledBridge(t, false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, br.addr, strings.Repeat("EF", 20), other.cert, "0")
	if err == nil {
		_ = conn.Close()
		t.Fatal("foreign transport certificate accepted")
	}
}

// TestControlledObfs4HandshakeCancellation proves ctx bounds a stalled
// handshake and the connection attempt is not orphaned.
func TestControlledObfs4HandshakeCancellation(t *testing.T) {
	t.Parallel()
	br := newControlledBridge(t, false, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, br.addr, strings.Repeat("12", 20), br.cert, "0")
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled handshake cancellation: %v", err)
	}
	select {
	case <-br.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server never observed the canceled attempt")
	}
}
