package gonion_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/robogg133/gonion"
)

func TestPublic_EmptyMsgReturnsSentinel(t *testing.T) {
	err := gonion.Public(gonion.ErrClosed, "")
	if err != gonion.ErrClosed {
		t.Fatalf("got %v want sentinel identity", err)
	}
}

func TestPublic_IsAndUnwrap(t *testing.T) {
	err := gonion.Public(gonion.ErrProtocolViolation, "expected CERTS")
	if !errors.Is(err, gonion.ErrProtocolViolation) {
		t.Fatal("errors.Is sentinel")
	}
	if errors.Is(err, gonion.ErrTLS) {
		t.Fatal("must not match unrelated sentinel")
	}
	if !strings.Contains(err.Error(), "gonion: protocol violation") {
		t.Fatalf("error string missing sentinel: %s", err)
	}
	if !strings.Contains(err.Error(), "expected CERTS") {
		t.Fatalf("error string missing msg: %s", err)
	}
}

func TestPublicf_Formats(t *testing.T) {
	err := gonion.Publicf(gonion.ErrVersion, "expected VERSIONS, got command %d", 7)
	if !errors.Is(err, gonion.ErrVersion) {
		t.Fatal(err)
	}
	if !strings.Contains(err.Error(), "got command 7") {
		t.Fatal(err)
	}
}

func TestPublic_NoSecretLeakConvention(t *testing.T) {
	// Callers should put digests only in logs; public msg stays generic.
	err := gonion.Public(gonion.ErrSendMe, "digest mismatch")
	if strings.Contains(err.Error(), "deadbeef") {
		t.Fatal("unexpected content")
	}
	if !errors.Is(err, gonion.ErrSendMe) {
		t.Fatal()
	}
}

func TestSentinels_UniqueMessages(t *testing.T) {
	all := []error{
		gonion.ErrClosed,
		gonion.ErrProtocolViolation,
		gonion.ErrHandshake,
		gonion.ErrTLS,
		gonion.ErrVersion,
		gonion.ErrCircuit,
		gonion.ErrExtend,
		gonion.ErrStream,
		gonion.ErrStreamClosed,
		gonion.ErrDecrypt,
		gonion.ErrInvalidHop,
		gonion.ErrSendMe,
		gonion.ErrIO,
		gonion.ErrTimeout,
		gonion.ErrBootstrap,
		gonion.ErrDirectory,
	}
	seen := map[string]bool{}
	for _, e := range all {
		s := e.Error()
		if s == "" {
			t.Fatal("empty sentinel message")
		}
		if !strings.HasPrefix(s, "gonion: ") {
			t.Fatalf("sentinel %q missing gonion: prefix", s)
		}
		if seen[s] {
			t.Fatalf("duplicate message %q", s)
		}
		seen[s] = true
	}
}
