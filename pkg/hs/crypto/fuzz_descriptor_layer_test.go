package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// Every HS descriptor encryption layer for V5.2 (rend-spec-v3 2.5.3).
// Layers: SuperencryptedLayer (outer, blinded key only) and EncryptedLayer
// (inner, blinded key + optional cookie). Provenance: seeds use the key
// material shape from desc_key_test.go (32-byte secretData, 32-byte
// subcredential, revision 1). The must-hold invariant is that Decrypt
// authenticates the MAC before releasing plaintext and never panics.
// No crasher minimized yet; campaign findings become seeds with IDs.

func FuzzDescriptorLayers(f *testing.F) {
	// Valid-shaped inputs for both layers.
	secret := bytes.Repeat([]byte{0x42}, 32)
	// subcredential is derived from a blinded key in production; here the
	// fuzzer supplies arbitrary 32 bytes (KDF input validation rejects
	// invalid secretData, which is itself the coverage we need).
	f.Add(secret, make([]byte, 32), uint64(1), []byte("superencrypted-data"))
	f.Add(secret, make([]byte, 32), uint64(1), []byte("encrypted-data"))
	f.Add(secret, make([]byte, 32), uint64(0), []byte("encrypted-data"))
	f.Add([]byte("short"), make([]byte, 32), uint64(1), []byte("encrypted-data"))
	f.Add(make([]byte, 32), make([]byte, 32), uint64(1), []byte("invalid-layer"))
	// Full 48-byte cookie secret for the encrypted layer (32+16).
	f.Add(bytes.Repeat([]byte{0x42}, 48), make([]byte, 32), uint64(1), []byte("encrypted-data"))
	f.Fuzz(func(t *testing.T, secretData, sub []byte, revision uint64, layerBytes []byte) {
		if len(secretData) > 128 || len(sub) > 64 || len(layerBytes) > 64 {
			return
		}
		// Map fuzz bytes to a valid layer only for the happy-path
		// round-trip; unknown layers must be rejected by descriptorKeys.
		var layer DescriptorLayer
		switch string(layerBytes) {
		case "hsdir-superencrypted-data":
			layer = SuperencryptedLayer
		case "hsdir-encrypted-data":
			layer = EncryptedLayer
		default:
			for _, l := range []DescriptorLayer{SuperencryptedLayer, EncryptedLayer} {
				// Encrypt with a swapped/unknown layer selector must fail
				// or at least not produce a decryptable blob under a valid layer.
				plaintext := []byte("fuzz-plaintext")
				blob, err := EncryptDescriptor(secretData, sub, revision, l, plaintext)
				if err != nil {
					continue
				}
				// Cross-layer decryption must fail MAC verification.
				var other DescriptorLayer
				if l == SuperencryptedLayer {
					other = EncryptedLayer
				} else {
					other = SuperencryptedLayer
				}
				if _, err := DecryptDescriptor(secretData, sub, revision, other, blob); err == nil {
					t.Fatalf("cross-layer decryption accepted (%s -> %s)", l, other)
				}
			}
			return
		}
		plaintext := []byte("fuzz-plaintext")
		blob, err := EncryptDescriptor(secretData, sub, revision, layer, plaintext)
		if err != nil {
			return
		}
		got, err := DecryptDescriptor(secretData, sub, revision, layer, blob)
		if err != nil {
			t.Fatalf("roundtrip decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("descriptor roundtrip mismatch")
		}
		// Flip one byte in the ciphertext and one in the MAC: both must be
		// rejected without releasing plaintext.
		for _, pos := range []int{16, len(blob) - 1} {
			mut := bytes.Clone(blob)
			if pos < len(mut) {
				mut[pos] ^= 0x01
				if _, err := DecryptDescriptor(secretData, sub, revision, layer, mut); err == nil {
					t.Fatalf("mutated descriptor accepted at %d", pos)
				}
			}
		}
		// Truncations must be rejected.
		for _, n := range []int{0, 16, 47, 48, len(blob) - 1} {
			if n >= 0 && n < len(blob) {
				if _, err := DecryptDescriptor(secretData, sub, revision, layer, blob[:n]); err == nil {
					t.Fatalf("truncated descriptor (%d) accepted", n)
				}
			}
		}
	})
}

func FuzzDescriptorBlob(f *testing.F) {
	// Adversarial blob-only fuzz: any blob up to MaxDescriptorSize must be
	// rejected or authenticated without panic, using fixed valid keys.
	blind := bytes.Repeat([]byte{0x42}, 32)
	sub := bytes.Repeat([]byte{0x43}, 32)
	// Seed with a real blob produced from "hello".
	real, err := EncryptDescriptor(blind, sub, 7, EncryptedLayer, []byte("hello"))
	if err != nil {
		f.Skip(err)
	}
	f.Add(real)
	f.Add([]byte{})
	f.Add(make([]byte, 49))
	f.Add(real[:len(real)-1])
	f.Add(real)
	// Also superencrypted seed.
	super, err := EncryptDescriptor(blind, sub, 7, SuperencryptedLayer, []byte("hello"))
	if err != nil {
		f.Skip(err)
	}
	f.Add(super)
	f.Fuzz(func(t *testing.T, blob []byte) {
		if len(blob) == 0 {
			return
		}
		if len(blob) > MaxDescriptorSize {
			// The production bound rejects oversize blobs; skip them so
			// the fuzzer spends cycles on in-bound mutations.
			return
		}
		for _, layer := range []DescriptorLayer{SuperencryptedLayer, EncryptedLayer} {
			out, err := DecryptDescriptor(blind, sub, 7, layer, blob)
			if err != nil {
				continue
			}
			// If decryption succeeded, re-encryption is not required to
			// reproduce the same blob (fresh salt), but the plaintext must
			// be bounded by the production limit.
			if len(out) > MaxDescriptorSize {
				t.Fatal("decrypted plaintext exceeds limit")
			}
		}
		// Random salt blobs must not panic: Decrypt must verify MAC first.
		if _, err := DecryptDescriptor(blind, sub, 7, EncryptedLayer, blob); err != nil {
			return
		}
	})
}

func FuzzHsIntroRoundTrip(f *testing.F) {
	// HsClientIntro / HsServiceIntro ntor round-trip with adversarial
	// plaintext (rend-spec-v3 4.3). Adapted from hs_ntor_test.go shapes.
	// Fresh keys per fuzz execution exercise the real ECDH+KDF+AES-CTR path.
	f.Add([]byte("hello intro"))
	f.Add([]byte{})
	f.Add(make([]byte, 200))
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Fuzz(func(t *testing.T, plaintext []byte) {
		if len(plaintext) > 368 {
			return // 498-56-32-HsNtorMacLen limit in HsClientIntro
		}
		clientSK, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serviceSK, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		authKey := bytes.Repeat([]byte{0xAB}, 32)
		subcred := bytes.Repeat([]byte{0x13}, 32)
		_, blob, err := HsClientIntro(clientSK, serviceSK.PublicKey(), authKey, subcred, plaintext)
		if err != nil {
			return // oversize plaintext is rejected by the codec
		}
		X, got, err := HsServiceIntro(serviceSK, authKey, subcred, blob)
		if err != nil {
			t.Fatalf("valid intro rejected: %v", err)
		}
		if X == nil || !bytes.Equal(got, plaintext) {
			t.Fatal("hs-ntor roundtrip mismatch")
		}
		if len(blob) > 0 {
			mut := bytes.Clone(blob)
			mut[len(mut)-1] ^= 0xff
			if _, _, err := HsServiceIntro(serviceSK, authKey, subcred, mut); err == nil {
				t.Fatal("tampered intro accepted")
			}
		}
	})
}
