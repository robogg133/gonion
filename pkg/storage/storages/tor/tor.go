// Package tor reads Tor consensus text caches and stores Gonion's hydrated
// snapshot separately. Neither cache format authenticates directory signatures.
package tor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/robogg133/gonion/pkg/common"
	jsonparser "github.com/robogg133/gonion/pkg/parsers/json"
	"github.com/robogg133/gonion/pkg/parsers/usual"
	"github.com/robogg133/gonion/pkg/storage"
)

const (
	cachedConsensusFile          = "cached-consensus"
	cachedMicrodescConsensusFile = "cached-microdesc-consensus"
	snapshotFile                 = "gonion-consensus.json"
)

type store struct {
	dir string
	mu  sync.Mutex
}

// ErrDataDirRequired is returned when New is called without an explicit storage
// directory. Gonion no longer silently reuses C Tor's implicit data directory:
// callers must choose and own the directory. To retain the old behavior during
// migration, pass tor.DefaultDataDir explicitly after selecting it for the
// process.
var ErrDataDirRequired = errors.New("tor storage: data directory is required")

// New returns a consensus store rooted at dir.
//
// Breaking change (security-required migration): an empty dir used to select C
// Tor's platform default data directory. It is now an error. Update callers to
// pass a dedicated, caller-owned directory, or tor.DefaultDataDir when that
// legacy location is deliberately intended.
func New(dir string) (storage.Storage, error) {
	if dir == "" {
		return nil, ErrDataDirRequired
	}
	return &store{dir: dir}, nil
}

func (s *store) StoreConsensus(c *common.Consensus) error {
	if err := c.Validate(); err != nil {
		return err
	}
	raw, err := (usual.Parser{}).Format(c)
	if err != nil {
		return err
	}
	b, err := (jsonparser.Parser{}).Format(c)
	if err != nil {
		return err
	}
	name := cachedConsensusFile
	if c.Flavor == common.ConsensusFlavorMicrodesc {
		name = cachedMicrodescConsensusFile
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if err := s.writeAtomic(name, raw); err != nil {
		return err
	}
	// The snapshot includes its original text, so a crash between these two
	// renames cannot combine descriptors with a different consensus.
	return s.writeAtomic(snapshotFile, b)
}

var (
	// syncDir is fsyncing the containing directory after a rename. Platform
	// implementations may be no-ops where directory fsync is unavailable.
	syncDir = syncDirectory
	// renamePath is the primitive used to publish a completed temporary file.
	renamePath = os.Rename
	// syncFile persists file contents before close.
	syncFile = func(f *os.File) error { return f.Sync() }
)

func (s *store) writeAtomic(name string, b []byte) error {
	f, err := os.CreateTemp(s.dir, ".gonion-consensus-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if n, err := f.Write(b); err != nil {
		f.Close()
		return err
	} else if n != len(b) {
		f.Close()
		return io.ErrShortWrite
	}
	if err := syncFile(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := renamePath(f.Name(), filepath.Join(s.dir, name)); err != nil {
		return err
	}
	// A completed rename is not durable until its containing directory is synced.
	// Some platforms/filesystems do not support directory fsync; those
	// implementations report success and rely on file-level sync plus rename.
	return syncDir(s.dir)
}

// GetConsensus prefers the newest microdesc document, retaining the hydrated
// snapshot on ties. An ns cache is a fallback, never relabeled as microdesc.
// Legacy JSON in cached-consensus is deliberately not treated as Tor text.
func (s *store) GetConsensus() (*common.Consensus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *common.Consensus
	var failures []error
	for _, name := range []string{snapshotFile, cachedMicrodescConsensusFile, cachedConsensusFile} {
		f, err := os.Open(filepath.Join(s.dir, name))
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var c *common.Consensus
		if name == snapshotFile {
			c, err = (jsonparser.Parser{}).Parse(f)
			if err == nil {
				_, err = (usual.Parser{}).Format(c)
			}
		} else {
			c, err = (usual.Parser{}).Parse(f)
			if err == nil && ((name == cachedConsensusFile && c.Flavor != common.ConsensusFlavorNS) || (name == cachedMicrodescConsensusFile && c.Flavor != common.ConsensusFlavorMicrodesc)) {
				err = fmt.Errorf("consensus cache: %s has flavor %q", name, c.Flavor)
			}
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if best == nil || c.ValidAfter.After(best.ValidAfter) || (c.ValidAfter.Equal(best.ValidAfter) && c.Flavor == common.ConsensusFlavorMicrodesc && best.Flavor != common.ConsensusFlavorMicrodesc) {
			best = c
		} else if c.ValidAfter.Equal(best.ValidAfter) && c.Flavor == best.Flavor && !bytes.Equal(c.RawDocument, best.RawDocument) {
			// Conflicting documents at the same epoch must not share hydration.
			return nil, fmt.Errorf("consensus cache: conflicting documents at the same valid-after")
		}
	}
	if best != nil {
		return best, nil
	}
	return nil, errors.Join(failures...)
}
