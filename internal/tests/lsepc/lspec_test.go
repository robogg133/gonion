package lsepc_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/robogg133/gonion/pkg/lspec"
)

var (
	expectedIpv4    = []byte{0, 6, 23, 191, 200, 67, 1, 187}
	expectedLegacy  = []byte{2, 20, 133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 133}
	expectedEd25519 = []byte{3, 32, 133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133}

	expectedLespcs = []byte{3, 0, 6, 23, 191, 200, 67, 1, 187, 2, 20, 133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 133, 3, 32, 133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133}
)

func TestLspecs(t *testing.T) {
	var buff bytes.Buffer
	w := &buff

	var lspecs []lspec.Lspec

	t.Run("IPv4", func(t *testing.T) {
		spec, err := lspec.NewLespecFromIPText("23.191.200.67:443")
		if err != nil {
			t.Fatal(err)
		}
		var buff bytes.Buffer
		spec.Write(&buff)

		if !bytes.Equal(buff.Bytes(), expectedIpv4) {
			t.Fatalf("expected %v, got %v", expectedIpv4, buff.Bytes())
		}
		lspecs = append(lspecs, spec)
	})
	t.Run("LegacyID", func(t *testing.T) {
		spec := lspec.NewNodeID([20]byte{133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 133})
		var buff bytes.Buffer
		spec.Write(&buff)

		if !bytes.Equal(buff.Bytes(), expectedLegacy) {
			t.Fatalf("expected %v, got %v", expectedLegacy, buff.Bytes())
		}
		lspecs = append(lspecs, spec)
	})
	t.Run("Ed25519", func(t *testing.T) {
		spec := lspec.NewEd25519ID([]byte{133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133})
		var buff bytes.Buffer
		spec.Write(&buff)

		if !bytes.Equal(buff.Bytes(), expectedEd25519) {
			t.Fatalf("expected %v, got %v", expectedEd25519, buff.Bytes())
		}
		lspecs = append(lspecs, spec)
	})

	if err := binary.Write(w, binary.BigEndian, uint8(len(lspecs))); err != nil {
		t.Fatal(err)
	}

	for _, v := range lspecs {
		if err := v.Write(w); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(buff.Bytes(), expectedLespcs) {
		t.Fatalf("expected %v, got %v", expectedLespcs, buff.Bytes())
	}
}
