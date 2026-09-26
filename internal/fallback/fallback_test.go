package fallback

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/robogg133/gonion/internal/shared"
)

func TestFallbackRejectsInvalidPinsAndCancellation(t *testing.T) {
	for _, fingerprint := range []string{"", "not-hex", "01", "0000000000000000000000000000000000000000"} {
		fb := New([]shared.FallbackDir{{IPv4: "127.0.0.1", ORPort: 1, Fingerprint: fingerprint}})
		if _, err := fb.DialContext(context.Background(), false); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(shared.Fallbacks).DialContext(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled fallback dial: %v", err)
	}
	if _, err := New(nil).Dial(false); err == nil {
		t.Fatal("empty fallback list accepted")
	}
}

func TestPinnedConnection(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	identity := [20]byte{1}
	c := &pinnedConn{Conn: a, identity: identity}
	if c.ExpectedRelayIdentity() != identity {
		t.Fatal("lost selected fallback identity")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{1}); err == nil {
		t.Fatal("wrapper did not close the underlying connection")
	}
}
