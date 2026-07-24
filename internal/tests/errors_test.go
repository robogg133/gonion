package tests

import (
	"errors"
	"strings"
	"testing"

	"github.com/robogg133/gonion"
)

func TestPublicErrors_IsSentinel(t *testing.T) {
	err := gonion.Public(gonion.ErrProtocolViolation, "expected CERTS")
	if !errors.Is(err, gonion.ErrProtocolViolation) {
		t.Fatalf("errors.Is failed: %v", err)
	}
	if errors.Is(err, gonion.ErrTLS) {
		t.Fatal("should not match unrelated sentinel")
	}
}

func TestPublicErrors_NoInternalLeakInSendMeStyle(t *testing.T) {
	// Public messages must not embed raw digests / secrets.
	err := gonion.Public(gonion.ErrSendMe, "digest mismatch")
	s := err.Error()
	if strings.Contains(s, "deadbeef") {
		t.Fatalf("leaked content: %s", s)
	}
	if !strings.Contains(s, "digest mismatch") {
		t.Fatalf("missing public msg: %s", s)
	}
	if !errors.Is(err, gonion.ErrSendMe) {
		t.Fatal("unwrap")
	}
}

func TestPublicf(t *testing.T) {
	err := gonion.Publicf(gonion.ErrVersion, "expected VERSIONS, got command %d", 7)
	if !errors.Is(err, gonion.ErrVersion) {
		t.Fatal(err)
	}
	if !strings.Contains(err.Error(), "got command 7") {
		t.Fatal(err)
	}
}

func TestStreamClosedSentinel(t *testing.T) {
	if gonion.ErrStreamClosed.Error() == "" {
		t.Fatal("empty")
	}
}
