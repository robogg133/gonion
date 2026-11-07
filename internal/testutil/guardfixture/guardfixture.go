// Package guardfixture provides real in-memory guard persistence for tests.
package guardfixture

import (
	"context"
	"sync"
	"testing"

	"github.com/robogg133/gonion/pkg/path"
)

// Manager returns a caller-owned in-memory persistence implementation. Snapshot
// bytes survive every Save for the manager's lifetime.
func Manager(t testing.TB) *path.GuardManager {
	t.Helper()
	var mu sync.Mutex
	var snapshot []byte
	m, err := path.NewGuardManager(context.Background(), path.GuardPersistence{
		Load: func(context.Context) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			return append([]byte(nil), snapshot...), nil
		},
		Save: func(_ context.Context, data []byte) error {
			mu.Lock()
			snapshot = append(snapshot[:0], data...)
			mu.Unlock()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
