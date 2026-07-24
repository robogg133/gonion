package lspec_test

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

	expectedLspecs = []byte{3, 0, 6, 23, 191, 200, 67, 1, 187, 2, 20, 133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 133, 3, 32, 133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133}
)

func TestLspec_IPv4_Write(t *testing.T) {
	spec, err := lspec.NewLespecFromIPText("23.191.200.67:443")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := spec.Write(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), expectedIpv4) {
		t.Fatalf("got %v want %v", buf.Bytes(), expectedIpv4)
	}
}

func TestLspec_LegacyID_Write(t *testing.T) {
	spec := lspec.NewNodeID([20]byte{133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 133})
	var buf bytes.Buffer
	if err := spec.Write(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), expectedLegacy) {
		t.Fatalf("got %v want %v", buf.Bytes(), expectedLegacy)
	}
}

func TestLspec_Ed25519_Write(t *testing.T) {
	spec := lspec.NewEd25519ID([]byte{133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133})
	var buf bytes.Buffer
	if err := spec.Write(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), expectedEd25519) {
		t.Fatalf("got %v want %v", buf.Bytes(), expectedEd25519)
	}
}

func TestLspec_ListEncoding(t *testing.T) {
	var lspecs []lspec.Lspec
	ip, err := lspec.NewLespecFromIPText("23.191.200.67:443")
	if err != nil {
		t.Fatal(err)
	}
	lspecs = append(lspecs,
		ip,
		lspec.NewNodeID([20]byte{133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 133}),
		lspec.NewEd25519ID([]byte{133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133}),
	)

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint8(len(lspecs))); err != nil {
		t.Fatal(err)
	}
	for _, v := range lspecs {
		if err := v.Write(&buf); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(buf.Bytes(), expectedLspecs) {
		t.Fatalf("got %v want %v", buf.Bytes(), expectedLspecs)
	}
}

func TestLspec_Read_RoundTrip_IPv4(t *testing.T) {
	spec, err := lspec.NewLespecFromIPText("1.2.3.4:9001")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := spec.Write(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := lspec.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type() != lspec.LSTYPE_IPV4 {
		t.Fatalf("type=%d", got.Type())
	}
}

func TestLspec_Read_UnknownType(t *testing.T) {
	raw := []byte{99, 1, 0x00}
	_, err := lspec.Read(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLspec_Read_TooBig(t *testing.T) {
	raw := []byte{0, 64}
	raw = append(raw, make([]byte, 64)...)
	_, err := lspec.Read(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected too big error")
	}
}

func TestLspec_NewEd25519ID_PanicsOnBadLen(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = lspec.NewEd25519ID([]byte{1, 2, 3})
}

func TestLspec_InvalidIPText(t *testing.T) {
	_, err := lspec.NewLespecFromIPText("not-an-address")
	if err == nil {
		t.Fatal("expected error")
	}
}
