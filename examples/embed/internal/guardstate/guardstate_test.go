package guardstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFailure(t *testing.T) {
	if _, err := New(context.Background(), t.TempDir()); err == nil {
		t.Fatal("accepted a directory as guard state")
	}
}

func TestSaveCancellationPreservesAtomicContent(t *testing.T) {
	name := filepath.Join(t.TempDir(), "guards.json")
	first := []byte(`{"version":1}`)
	if err := save(context.Background(), name, first); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := save(ctx, name, []byte(`{"version":2}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save: %v", err)
	}
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("atomic content changed after canceled save: %q", got)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
}
