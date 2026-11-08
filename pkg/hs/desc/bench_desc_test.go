package desc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"testing"
	"time"

	hscrypto "github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/lspec"
)

// O6.1 HS descriptor baselines. Mirrors testOptions in desc_test.go but uses
// a *testing.B harness; do not call testOptions (it requires *testing.T).
// Both encryption layers (superencrypted + encrypted) are exercised via Encode.

func benchTestOptions(b *testing.B) EncodeOptions {
	b.Helper()
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	blinded, err := hscrypto.BlindPrivateKey(identity, 1234, 1440)
	if err != nil {
		b.Fatal(err)
	}
	relayKey, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		b.Fatal(err)
	}
	encKey, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		b.Fatal(err)
	}
	auth := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	relayID := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	addr, err := lspec.FromWire(0, []byte{127, 0, 0, 1, 0x23, 0x29})
	if err != nil {
		b.Fatal(err)
	}
	return EncodeOptions{
		BlindedKey:        blinded,
		SigningKey:        ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32)),
		RevisionCounter:   1<<63 + 42,
		CertificateExpiry: time.Now().Add(48 * time.Hour),
		IntroPoints:       []IntroPoint{{OnionKey: relayKey.PublicKey().Bytes(), EncKey: encKey.PublicKey().Bytes(), AuthKey: auth[32:], LinkSpecs: []lspec.Lspec{addr, lspec.NewNodeID([20]byte{7}), lspec.NewEd25519ID(ed25519.PublicKey(relayID[32:]))}}},
	}
}

func BenchmarkDescriptorEncode(b *testing.B) {
	o := benchTestOptions(b)
	raw, err := Encode(o)
	if err != nil {
		b.Fatal(err)
	}
	if len(raw) == 0 {
		b.Fatal("empty descriptor")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, err := Encode(o)
		if err != nil {
			b.Fatal(err)
		}
		_ = raw
	}
}

func BenchmarkDescriptorDecode(b *testing.B) {
	o := benchTestOptions(b)
	raw, err := Encode(o)
	if err != nil {
		b.Fatal(err)
	}
	blinded := o.BlindedKey.PublicKey()
	now := time.Now()
	if _, err := Decode(raw, blinded, nil, now); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, err := Decode(raw, blinded, nil, now)
		if err != nil {
			b.Fatal(err)
		}
		if d.Version != 3 || len(d.IntroPoints) != 1 {
			b.Fatalf("bad descriptor: %+v", d)
		}
	}
}

func BenchmarkDescriptorParseOuter(b *testing.B) {
	o := benchTestOptions(b)
	raw, err := Encode(o)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, err := Parse(raw)
		if err != nil {
			b.Fatal(err)
		}
		_ = d
	}
}
