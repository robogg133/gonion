package onion_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/robogg133/gonion/pkg/hs/onion"
)

const testAddr = "tbup4alxvo3wmessgrbjfbfpny6x5xab56do6sli6i6b42sgreisrfqd.onion"

func TestOnionAddrFromString(t *testing.T) {
	o, err := onion.NewFromString(testAddr + ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pk=%x,pk_len=%d,version=%d", o.Pk, len(o.Pk), o.Version)
}

func TestOnionAddr(t *testing.T) {
	o, err := onion.NewFromString(testAddr)
	if err != nil {
		t.Fatal(err)
	}

	addr := strings.TrimSuffix(o.String(), ".onion")
	if len(addr) != 56 {
		t.Fatal("onion addr must be 56 char len")
	}
	t.Log(o.String())
}

func TestIsOnion(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{testAddr + ":80", true},
		{"example.com:80", false},
	}
	for _, tt := range tests {
		got, err := onion.IsOnion(tt.addr)
		if err != nil {
			t.Fatalf("IsOnion(%q): %v", tt.addr, err)
		}
		if got != tt.want {
			t.Fatalf("IsOnion(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
	if _, err := onion.IsOnion("missing-port"); err == nil {
		t.Fatal("malformed dial address accepted")
	}
}

func TestRejectsTorsionPublicKey(t *testing.T) {
	// C Tor's order-8l torsion test vector from test_crypto_ed25519_validation.
	pk, err := hex.DecodeString("300ef2e64e588e1df55b48e4da0416ffb64cc85d5b00af6463d5cc6c2b1c185e")
	if err != nil {
		t.Fatal(err)
	}
	o := &onion.OnionHostname{Version: 3}
	copy(o.Pk[:], pk)
	if _, err := onion.NewFromString(o.String()); err == nil || !strings.Contains(err.Error(), "torsion") {
		t.Fatalf("torsion key error = %v", err)
	}
}
