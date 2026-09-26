package obfs4

import (
	"context"
	"errors"
	"testing"
)

func TestDialContextCancellationBeforeIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := DialContext(ctx, "", "", "", "")
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled transport dial: %v", err)
	}
}

func TestDialContextRejectsInvalidArguments(t *testing.T) {
	conn, err := DialContext(context.Background(), "", "", "not-a-cert", "0")
	if conn != nil || err == nil {
		t.Fatal("invalid transport certificate accepted")
	}
}
