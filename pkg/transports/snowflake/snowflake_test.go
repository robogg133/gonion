package snowflake

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	snowflake_client "gitlab.torproject.org/robogg133/snowflake-with-logging-setting/v2/client/lib"
)

func TestPinnedConnectionCloseAndMetadata(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	pin := [20]byte{1}
	c := &pinnedConn{Conn: raw, identity: pin}
	if c.ExpectedRelayIdentity() != pin {
		t.Fatal("missing relay identity metadata")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestDefaultsAndPreDialValidation(t *testing.T) {
	a, b := DefaultOptions(), DefaultOptions()
	if a.BridgeFingerprint != DefaultBridgeFingerprint || len(a.FrontDomains) == 0 || len(a.ICEAddresses) == 0 || a.KeepLocalAddresses || a.Max != 1 || a.Log == nil {
		t.Fatal("incomplete defaults")
	}
	a.ICEAddresses[0], a.FrontDomains[0] = "changed", "changed"
	if b.ICEAddresses[0] == "changed" || b.FrontDomains[0] == "changed" {
		t.Fatal("shared mutable defaults")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DialContext(ctx, b); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, pin := range []string{"", "invalid", "0000000000000000000000000000000000000000"} {
		b.BridgeFingerprint = pin
		if _, err := DialContext(context.Background(), b); err == nil {
			t.Fatal("invalid pin accepted")
		}
	}
}

func TestDialContextClosesLateConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started, release := make(chan struct{}), make(chan struct{})
	raw, peer := net.Pipe()
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		_, err := dialContext(ctx, func() (net.Conn, error) { close(started); <-release; return raw, nil })
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late connection not closed")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("late close timed out")
	}
}

func TestDialContextTransfersOwnership(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := dialContext(ctx, func() (net.Conn, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = peer.Write([]byte{42}) }()
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil || buf[0] != 42 {
		t.Fatalf("completed connection tied to context: %v", err)
	}
	for _, fail := range []bool{false, true} {
		raw, peer := net.Pipe()
		_, err := dialContext(context.Background(), func() (net.Conn, error) {
			if fail {
				return raw, errors.New("failed")
			}
			_ = raw.Close()
			return nil, nil
		})
		if err == nil {
			t.Fatal("bad dial result accepted")
		}
		if _, err := peer.Write([]byte{1}); err == nil {
			t.Fatal("failed dial leaked connection")
		}
		_ = peer.Close()
	}
}

// TestFrontedAndUnfrontedConfigurationsAreSeparate keeps the two Snowflake
// configuration classes distinct (E4.4): the fronted default fronts broker
// polling over CDN domains, while UnfrontedOptions selects the direct
// rendezvous and must still carry the mandatory bridge pin and stay silent.
// Pre-dial validation must behave identically for both classes.
func TestFrontedAndUnfrontedConfigurationsAreSeparate(t *testing.T) {
	fronted := DefaultOptions()
	unfronted := UnfrontedOptions()
	if len(fronted.FrontDomains) == 0 || fronted.FrontDomain != "" {
		t.Fatal("fronted defaults changed")
	}
	if unfronted.FrontDomains != nil || unfronted.FrontDomain != "" {
		t.Fatal("unfronted configuration still fronts")
	}
	if unfronted.BrokerURL != DefaultBroker || unfronted.BridgeFingerprint != DefaultBridgeFingerprint {
		t.Fatal("unfronted lost the broker/pin defaults")
	}
	if unfronted.Log == nil || unfronted.KeepLocalAddresses || unfronted.Max != 1 || len(unfronted.ICEAddresses) == 0 {
		t.Fatal("unfronted lost silence or ICE hygiene defaults")
	}
	for name, cfg := range map[string]snowflake_client.ClientConfig{"fronted": fronted, "unfronted": unfronted} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := DialContext(ctx, cfg); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s pre-dial cancellation: %v", name, err)
		}
		cfg.BridgeFingerprint = ""
		if _, err := DialContext(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "fingerprint") {
			t.Fatalf("%s accepted an unpinned bridge: %v", name, err)
		}
	}
}

// TestUpstreamForkRecorded pins the evidence provenance constant used by
// transport reports.
func TestUpstreamForkRecorded(t *testing.T) {
	if !strings.Contains(UpstreamVersion, "aff631a5b504") {
		t.Fatalf("upstream fork version not recorded: %q", UpstreamVersion)
	}
}
