// Package guardstate supplies caller-owned durable public-guard state for the examples.
package guardstate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/robogg133/gonion/pkg/path"
)

func New(ctx context.Context, name string) (*path.GuardManager, error) {
	if name == "" {
		return nil, fmt.Errorf("provide -guard-state with a caller-owned state file")
	}
	return path.NewGuardManager(ctx, path.GuardPersistence{
		Load: func(ctx context.Context) ([]byte, error) { return load(ctx, name) },
		Save: func(ctx context.Context, data []byte) error { return save(ctx, name, data) },
	})
}

func load(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(name)
	if err != nil && os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

func save(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(name)
	file, err := os.CreateTemp(dir, ".gonion-guards-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	err = file.Chmod(0600)
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !isUnsupportedSync(err) {
		return err
	}
	return nil
}

func isUnsupportedSync(err error) bool {
	return errors.Is(err, fs.ErrInvalid)
}
