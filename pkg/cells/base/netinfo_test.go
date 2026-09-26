package cells

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"testing"
)

// Hand-encoded from tor-spec 4.5: TIME, ATYPE, ALEN, AVAL, NMYADDR.
func netinfoVector(t *testing.T, prefix string) []byte {
	t.Helper()
	b, err := hex.DecodeString(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, make([]byte, CELL_BODY_LEN-len(b))...)
}

func TestNetinfoTruncatedAddressesReturnError(t *testing.T) {
	valid := netinfoVector(t, "0000000004047f00000101061000000000000000000000000000000001")
	for n := 0; n < len(valid); n++ {
		var c NetInfoCell
		if err := c.Decode(bytes.NewReader(valid[:n])); err == nil {
			t.Fatalf("accepted truncated payload of %d bytes", n)
		}
	}
}

func TestNetinfoAddressLengthsAndReuse(t *testing.T) {
	for _, other := range []string{"0403010203", "0603010203", "ff03010203"} {
		// Invalid/unknown addresses are ignored, but ALEN bytes must be consumed.
		b := netinfoVector(t, "00000000"+other+"0204047f000001061000000000000000000000000000000001")
		var c NetInfoCell
		if err := c.Decode(bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
		if c.OtherAddr.IsValid() || len(c.MyAdress) != 2 || c.MyAdress[0] != netip.MustParseAddr("127.0.0.1") || c.MyAdress[1] != netip.IPv6Loopback() {
			t.Fatalf("bad decoded addresses: %+v", c)
		}
		if err := c.Decode(bytes.NewReader(netinfoVector(t, "0000000004047f00000100"))); err != nil {
			t.Fatal(err)
		}
		if len(c.MyAdress) != 0 {
			t.Fatal("retained addresses from previous cell")
		}
	}
}

func TestNetinfoExcessAddressCount(t *testing.T) {
	b := netinfoVector(t, "0000000004047f000001ff")
	var c NetInfoCell
	if err := c.Decode(bytes.NewReader(b)); err == nil {
		t.Fatal("accepted addresses exceeding fixed payload")
	}
}

func FuzzNetinfoDecode(f *testing.F) {
	f.Add(make([]byte, CELL_BODY_LEN))
	f.Add([]byte{0, 0, 0, 0, 4, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		var c NetInfoCell
		_ = c.Decode(bytes.NewReader(b))
	})
}

type netinfoFailWriter struct{ remaining int }

func (w *netinfoFailWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, io.ErrClosedPipe
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestNetinfoEncodeValidationAndWriteFailure(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	for _, c := range []NetInfoCell{
		{},
		{OtherAddr: ip, MyAdress: []netip.Addr{{}}},
		{OtherAddr: ip, MyAdress: make([]netip.Addr, 256)},
	} {
		if err := c.Encode(io.Discard); err == nil {
			t.Fatal("accepted invalid NETINFO addresses")
		}
	}
	c := NetInfoCell{OtherAddr: ip, MyAdress: []netip.Addr{ip}}
	if err := c.Encode(&netinfoFailWriter{remaining: 11}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost address write failure: %v", err)
	}
}
