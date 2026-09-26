package crypto

import (
	"bytes"
	"testing"
)

func TestTorHSIndexVectors(t *testing.T) {
	// C Tor src/test/test_hs_common.c:test_hs_indexes, default 1440 minutes.
	key := bytes.Repeat([]byte{0x42}, 32)
	b := &BlindedPublicKey{blindPk: key, periodNumber: 42, periodLenght: 1440}
	if got := b.ServiceIndex(1); !bytes.Equal(got, hexBytes(t, "37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a")) {
		t.Fatalf("service index: %x", got)
	}
	if got := RelayIndex(key, bytes.Repeat([]byte{0x43}, 32), 42, 1440); !bytes.Equal(got, hexBytes(t, "db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5")) {
		t.Fatalf("relay index: %x", got)
	}
	if b.ServiceIndex(0) != nil || b.ServiceIndex(17) != nil || (*BlindedPublicKey)(nil).ServiceIndex(1) != nil {
		t.Fatal("invalid service index input accepted")
	}
}
