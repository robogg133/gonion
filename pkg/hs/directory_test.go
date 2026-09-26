package hs

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/crypto"
)

func TestClientSRVSchedule(t *testing.T) {
	// rend-spec-v3 CLIENTFETCH: C1 at 13:00 uses current; C2 at 01:00
	// uses previous, with the same period and SRV on either side of midnight.
	at := time.Date(2016, 4, 12, 13, 0, 0, 0, time.UTC)
	c := &common.Consensus{ValidAfter: at, FreshUntil: at.Add(time.Hour), SharedCurrentValue: [32]byte{1}, HasSharedCurrentValue: true}
	period := c.CalcPeriodNum()
	if got := clientSRV(c, period, 1440); got != c.SharedCurrentValue {
		t.Fatalf("afternoon SRV: %x", got)
	}
	c.ValidAfter = c.ValidAfter.Add(12 * time.Hour)
	c.FreshUntil = c.ValidAfter.Add(time.Hour)
	c.SharedPreviousValue, c.HasSharedPreviousValue = c.SharedCurrentValue, true
	c.SharedCurrentValue = [32]byte{2}
	if c.CalcPeriodNum() != period || clientSRV(c, period, 1440) != c.SharedPreviousValue {
		t.Fatal("midnight changed client period or SRV")
	}
	c.SharedPreviousValue = [32]byte{}
	if clientSRV(c, period, 1440) != [32]byte{} {
		t.Fatal("signed zero SRV treated as absent")
	}
	c.HasSharedPreviousValue = false
	input := binary.BigEndian.AppendUint64([]byte("shared-random-disaster"), 1440)
	input = binary.BigEndian.AppendUint64(input, period)
	if clientSRV(c, period, 1440) != sha3.Sum256(input) {
		t.Fatal("incorrect disaster SRV")
	}
}

func TestHSDirWrapAndReplicas(t *testing.T) {
	// Fixed identities are hashed using the field ordering specified in
	// rend-spec-v3 WHERE-HSDESC; max index forces wrap-around.
	c := &common.Consensus{ValidAfter: time.Unix(1460546101, 0), FreshUntil: time.Unix(1460549701, 0)}
	for i := byte(1); i <= 8; i++ {
		r := common.RouterStatus{NodeID: [20]byte{i}, IdEd25519: bytes.Repeat([]byte{i}, 32)}
		r.StatusFlags[common.FLAG_HIDDEN_SERVICE_DIR] = true
		r.ProtoVersions.HSDir.SetValue(common.VERSION_2, true)
		c.RelayInformation = append(c.RelayInformation, r)
	}
	c.RelayInformation[7].ProtoVersions.HSDir.SetValue(common.VERSION_2, false)
	srv := clientSRV(c, 16903, 1440)
	wrapped, err := hsdirRing(srv[:], 16903, 1440, c.RelayInformation, bytes.Repeat([]byte{255}, 32))
	if err != nil || len(wrapped) != 7 {
		t.Fatalf("ring: %d %v", len(wrapped), err)
	}
	for i := 1; i < len(wrapped); i++ {
		prev := crypto.RelayIndex(wrapped[i-1].IdEd25519, srv[:], 16903, 1440)
		next := crypto.RelayIndex(wrapped[i].IdEd25519, srv[:], 16903, 1440)
		if bytes.Compare(prev, next) >= 0 {
			t.Fatal("ring did not wrap to smallest index")
		}
	}
	// Identity from the Tor key-blinding vector used in crypto tests.
	identity := []byte{0x58}
	identity = append(identity, bytes.Repeat([]byte{0x66}, 31)...)
	bpk, err := crypto.BlindPublicKey(identity, 16903, 1440)
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := responsibleHSDirs(c, bpk, 16903, 1440)
	if err != nil || len(dirs) != 6 {
		t.Fatalf("replicas: %d %v", len(dirs), err)
	}
	seen := make(map[[20]byte]bool)
	for _, r := range dirs {
		if seen[r.NodeID] {
			t.Fatal("duplicate directory across replicas")
		}
		seen[r.NodeID] = true
	}
	c.Params = map[string]int32{"hsdir_n_replicas": 16, "hsdir_spread_fetch": 128}
	dirs, err = responsibleHSDirs(c, bpk, 16903, 1440)
	if err != nil || len(dirs) != 7 {
		t.Fatalf("small ring exhausted incorrectly: %d %v", len(dirs), err)
	}
}
