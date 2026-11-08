package lspec_test

import (
	"bytes"
	"testing"

	"github.com/robogg133/gonion/pkg/lspec"
)

// Link-specifier fuzzing for V5.2 (tor-spec 4.1 EXTEND2 link specifiers).
// Provenance: seeds are the wire vectors from lspec_test.go
// (IPv4, LegacyID, Ed25519ID). Unknown specifiers must survive opaque
// round-trips verbatim; truncated/invalid specifiers must be rejected
// without desynchronizing the EXTEND2 list. No crasher minimized yet.

func FuzzLspecRead(f *testing.F) {
	f.Add([]byte{0, 6, 23, 191, 200, 67, 1, 187})
	f.Add([]byte{2, 20, 133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 133})
	f.Add([]byte{3, 32, 133, 0, 23, 12, 34, 123, 153, 123, 23, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133})
	f.Add([]byte{99, 4, 1, 2, 3, 4}) // unknown type, opaque round-trip
	f.Add([]byte{})
	f.Add([]byte{3, 1, 0})    // truncated Ed25519 body
	f.Add([]byte{0, 6, 1, 2}) // truncated IPv4 body
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 512 {
			return
		}
		spec, err := lspec.Read(bytes.NewReader(b))
		if err != nil {
			return
		}
		// Re-encode must be bounded and re-readable.
		var out bytes.Buffer
		if err := spec.Write(&out); err != nil {
			t.Fatalf("decoded lspec does not write: %v", err)
		}
		if out.Len() != len(b) {
			t.Fatalf("lspec roundtrip length %d vs %d", out.Len(), len(b))
		}
		if !bytes.Equal(out.Bytes(), b) {
			t.Fatal("lspec roundtrip bytes differ")
		}
		// Bytes is the body without the TYPE/LEN header; FromWire must not
		// panic on any body and must reject malformed ones.
		body, err := spec.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if len(body)+2 != out.Len() {
			t.Fatal("lspec body length inconsistent with wire encoding")
		}
		_, _ = lspec.FromWire(spec.Type(), body)
	})
}

func FuzzFromWire(f *testing.F) {
	f.Add(uint8(0), []byte{127, 0, 0, 1, 0, 80})
	f.Add(uint8(2), make([]byte, 20))
	f.Add(uint8(3), make([]byte, 32))
	f.Add(uint8(255), []byte{1, 2, 3})
	f.Add(uint8(0), []byte{})
	f.Fuzz(func(t *testing.T, typ uint8, body []byte) {
		if len(body) > 64 {
			return
		}
		spec, err := lspec.FromWire(typ, body)
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := spec.Write(&out); err != nil {
			t.Fatalf("FromWire spec does not write: %v", err)
		}
		if _, err := lspec.Read(bytes.NewReader(out.Bytes())); err != nil {
			t.Fatalf("FromWire spec not readable: %v", err)
		}
	})
}
