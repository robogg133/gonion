package fallback

import (
	"context"

	"net"

	"testing"

	"github.com/robogg133/gonion/internal/shared"
)

func TestSelectedFallbackRedialDoesNotSubstituteRelay(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	p1 := first.Addr().(*net.TCPAddr).Port
	p2 := second.Addr().(*net.TCPAddr).Port
	dirs := []shared.FallbackDir{
		{IPv4: "127.0.0.1", ORPort: uint16(p1), Fingerprint: "0101010101010101010101010101010101010101"},
		{IPv4: "127.0.0.1", ORPort: uint16(p2), Fingerprint: "0202020202020202020202020202020202020202"},
	}
	initial, err := New(dirs).DialContext(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer initial.Close()
	pinned := initial.(interface {
		ExpectedRelayIdentity() [20]byte
		RedialExpectedRelay(context.Context, [20]byte) (net.Conn, error)
	})
	if _, err := pinned.RedialExpectedRelay(context.Background(), [20]byte{2}); err == nil {
		t.Fatal("wrong pin accepted")
	}
	retry, err := pinned.RedialExpectedRelay(context.Background(), pinned.ExpectedRelayIdentity())
	if err != nil {
		t.Fatal("same relay not redialed:", err)
	}
	_ = retry.Close()
	_ = first.Close()
	if conn, err := pinned.RedialExpectedRelay(context.Background(), pinned.ExpectedRelayIdentity()); err == nil {
		_ = conn.Close()
		t.Fatal("unavailable selected fallback replaced with different relay")
	}
}
