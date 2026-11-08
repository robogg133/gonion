package crypto

import (
	"bytes"
	"crypto/sha1"
	"testing"
	"time"
)

// Benchmarks for O6.1 baselines. Focused, offline, deterministic fixtures:
// no network or public consensus is used. Fixture provenance is the existing
// cert2/cert4/cert5/cert7/tls set in pkg/crypto/testdata (see README in that
// directory); nothing is altered here, only measured.

func BenchmarkParseIdentityVSigningCert(b *testing.B) {
	if _, err := ParseIdentityVSigningCert(cert4Bytes); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := ParseIdentityVSigningCert(cert4Bytes)
		if err != nil {
			b.Fatal(err)
		}
		_ = got
	}
}

func BenchmarkVerifyRelayCertificates(b *testing.B) {
	when := time.Date(2026, 10, 20, 16, 0, 0, 0, time.UTC)
	certs := map[uint8][]byte{
		2: bytes.Clone(cert2Bytes),
		4: bytes.Clone(cert4Bytes),
		5: bytes.Clone(cert5Bytes),
		7: bytes.Clone(cert7Bytes),
	}
	if _, _, err := verifyRelayCertificates(certs, tlsBytes, when); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := verifyRelayCertificates(certs, tlsBytes, when); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyConnection(b *testing.B) {
	when := time.Date(2026, 10, 20, 16, 0, 0, 0, time.UTC)
	c4, err := ParseIdentityVSigningCert(cert4Bytes)
	if err != nil {
		b.Fatal(err)
	}
	c5, err := ParseIdentityVSigningCert(cert5Bytes)
	if err != nil {
		b.Fatal(err)
	}
	if err := verifyConnection(c4, c5, tlsBytes, when); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := verifyConnection(c4, c5, tlsBytes, when); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveKeysCreateFast(b *testing.B) {
	var x, y [20]byte
	for i := range x {
		x[i] = byte(i)
		y[i] = byte(255 - i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keys, err := DeriveKeysCreateFast(x, y)
		if err != nil {
			b.Fatal(err)
		}
		_ = keys
	}
}

// The standard relay body is 509 bytes (tor-spec 6.1). XORKeyStream is
// per-hop AES-CTR; the benchmark measures steady-state per-cell cost and
// allocations including the RunningValues mutex.
func BenchmarkRunningValuesXORKeyStream509(b *testing.B) {
	key := bytes.Repeat([]byte{0xab}, 16)
	seed := bytes.Repeat([]byte{0xcd}, 20)
	plain := make([]byte, 509)
	for i := range plain {
		plain[i] = byte(i)
	}
	rv, err := NewRunningValues(key, seed)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 509)
	b.SetBytes(509)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rv.XORKeyStream(dst, plain)
	}
}

func BenchmarkRunningValuesWrite509(b *testing.B) {
	key := bytes.Repeat([]byte{1}, 16)
	seed := bytes.Repeat([]byte{2}, 20)
	rv, err := NewRunningValues(key, seed)
	if err != nil {
		b.Fatal(err)
	}
	plain := make([]byte, 509)
	b.SetBytes(509)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rv.Write(plain); err != nil {
			b.Fatal(err)
		}
	}
}

// CheckDigest rolls back a snapshot on a mismatched 4-byte expected prefix.
// This exercises the tor-spec 6.1 "update a digest only when a cell is
// recognized" path with an incompatible payload.
func BenchmarkRunningValuesCheckDigestUnrecognized(b *testing.B) {
	key := bytes.Repeat([]byte{1}, 16)
	seed := bytes.Repeat([]byte{2}, 20)
	rv, err := NewRunningValues(key, seed)
	if err != nil {
		b.Fatal(err)
	}
	plain := make([]byte, 509)
	plain[0], plain[4], plain[10], plain[11] = 2, 1, 1, 42
	b.SetBytes(509)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok, err := rv.CheckDigest(plain, []byte{0, 0, 0, 0}); err != nil || ok {
			b.Fatalf("unexpected recognition: %v", err)
		}
	}
}

// Recognized check: build one fresh RunningValues per 100 iterations reserve
// is not allowed in the timed region, so precompute a recognized pair and
// clone the hash via MarshalBinary outside the timer for the naive setup,
// then inside the timer run CheckDigest against a new input whose digest is
// the post-write sum. The reference digest is a standard sha1 over seed+data.
func BenchmarkRunningValuesCheckDigestRecognized(b *testing.B) {
	key := bytes.Repeat([]byte{1}, 16)
	seed := bytes.Repeat([]byte{2}, 20)
	plain := make([]byte, 509)
	copy(plain, []byte{2, 0, 0})
	// Reference sha1 over digest-starting seed plus the cell.
	h := sha1.New()
	h.Write(seed)
	h.Write(plain)
	want := h.Sum(nil)
	rv, err := NewRunningValues(key, seed)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(509)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Each iteration uses a fresh hop so CheckDigest starts from the
		// known seed state; construction time is reported with the check
		// to make the work per iteration explicit (see BENCHMARKS.md).
		fresh, err := NewRunningValues(key, seed)
		if err != nil {
			b.Fatal(err)
		}
		got, ok, err := fresh.CheckDigest(plain, want[:4])
		if err != nil || !ok || len(got) != 20 {
			b.Fatalf("recognized digest not accepted: %v", err)
		}
		_ = rv
	}
}

func BenchmarkHSRunningValuesXORKeyStream509(b *testing.B) {
	key := bytes.Repeat([]byte{0xab}, 32)
	seed := bytes.Repeat([]byte{0xcd}, 32)
	plain := make([]byte, 509)
	for i := range plain {
		plain[i] = byte(i)
	}
	rv, err := NewHSRunningValues(key, seed)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 509)
	b.SetBytes(509)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rv.XORKeyStream(dst, plain)
	}
}

func BenchmarkHSRunningValuesWrite509(b *testing.B) {
	key := bytes.Repeat([]byte{1}, 32)
	seed := bytes.Repeat([]byte{2}, 32)
	rv, err := NewHSRunningValues(key, seed)
	if err != nil {
		b.Fatal(err)
	}
	plain := make([]byte, 509)
	b.SetBytes(509)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rv.Write(plain); err != nil {
			b.Fatal(err)
		}
	}
}
