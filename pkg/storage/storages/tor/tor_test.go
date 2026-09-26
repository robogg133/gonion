package tor

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/robogg133/gonion/pkg/parsers/usual"
)

func TestStoreReload(t *testing.T) {
	for _, tc := range []struct{ fixture, name string }{{"consensus.txt", cachedConsensusFile}, {"consensus-microdesc.txt", cachedMicrodescConsensusFile}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			data, err := os.ReadFile("../../../../internal/tests/" + tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			c, err := (usual.Parser{}).Parse(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			// Keep the storage check small; parser tests cover the full relay set.
			c.RelayInformation = c.RelayInformation[:min(3, len(c.RelayInformation))]
			if err := New(dir).StoreConsensus(c); err != nil {
				t.Fatal(err)
			}
			got, err := New(dir).GetConsensus()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c, got) {
				t.Fatal("snapshot lost fields")
			}
			raw, err := os.ReadFile(filepath.Join(dir, tc.name))
			if err != nil || !bytes.Equal(raw, data) {
				t.Fatal("wrong raw document", err)
			}
			for _, name := range []string{tc.name, snapshotFile} {
				fi, err := os.Stat(filepath.Join(dir, name))
				if err != nil || fi.Mode().Perm() != 0600 {
					t.Fatal("wrong permissions", err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, snapshotFile), []byte("truncated"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := New(dir).GetConsensus(); err != nil {
				t.Fatal("raw fallback failed", err)
			}
		})
	}
}

func TestRejectMislabeledCache(t *testing.T) {
	data, err := os.ReadFile("../../../../internal/tests/consensus-microdesc.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{data, []byte(`{"NetowrkStatusVersion":3}`)} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, cachedConsensusFile), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(dir).GetConsensus(); err == nil {
			t.Fatal("accepted mislabeled or legacy JSON cache")
		}
	}
}
