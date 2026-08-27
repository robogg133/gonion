package tor

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

func TestStoreReload(t *testing.T) {
	dir := t.TempDir()

	st := New(dir)
	c := &common.Consensus{
		NetowrkStatusVersion: 3,
		ValidAfter:           time.Date(2026, 1, 30, 22, 0, 0, 0, time.UTC),
		FreshUntil:           time.Date(2026, 1, 30, 23, 0, 0, 0, time.UTC),
		ValidUntil:           time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC),
		BandWidthWeight:      common.BandWidthWeight{Wgg: 1},
		RelayInformation: []common.RouterStatus{{
			Nickname: "relay1",
			NodeID:   [20]byte{1},
			Ipv4Addr: "1.2.3.4",
			ORPort:   9001,
		}},
	}

	if err := st.StoreConsensus(c); err != nil {
		t.Fatal(err)
	}

	got, err := New(dir).GetConsensus()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("reloaded consensus mismatch:\ngot  %+v\nwant %+v", got, c)
	}

	fi, err := os.Stat(filepath.Join(dir, cachedConsensusFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("cached-consensus mode = %o, want 600", fi.Mode().Perm())
	}

	if _, err := New(dir + "/missing").GetConsensus(); err == nil {
		t.Fatal("expected error for missing dir")
	}
}