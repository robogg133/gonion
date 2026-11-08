package desc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	hscrypto "github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/lspec"
)

// Descriptor decode + both encryption layers for V5.2. Provenance: seeds are
// a real Encode() output from the bench/Test options shape plus the outer
// wrapper literals in FuzzDescriptorParsers (desc_test.go). FuzzDescriptorParsers
// covers parseOuter/parseInner/decodeLinkSpecs/parseCertificate; this target
// covers full Decode (outer + superencrypted + encrypted + client-auth
// branch) so every layer is authenticated. No crasher minimized yet.

func FuzzDescriptorDecode(f *testing.F) {
	f.Add([]byte("hs-descriptor 3\n"))
	f.Add([]byte("create2-formats 2\n"))
	f.Add([]byte{3, 0, 6, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte("a"), 1000))
	// Valid blob seed: encode once with fixed test keys so the fuzzer starts
	// from a fully authenticated descriptor and can mutate it to cover MAC,
	// outer signature, and padding branches.
	blinded, err := hscrypto.BlindPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), 1234, 1440)
	if err != nil {
		f.Skip(err)
	}
	blob, err := seedValidDescriptor(blinded)
	if err != nil {
		f.Skip(err)
	}
	f.Add(blob)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxDescriptorSize+1 {
			return
		}
		blinded, err := hscrypto.BlindPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), 1234, 1440)
		if err != nil {
			t.Fatal(err)
		}
		// Public-service decode (no client auth key).
		d, err := Decode(b, blinded.PublicKey(), nil, time.Unix(1502661599, 0))
		if err != nil {
			// Also try with a client auth key so the authorized branch
			// (decryptMiddle client matching) is exercised.
			client, err2 := ecdh.X25519().GenerateKey(rand.Reader)
			if err2 != nil {
				return
			}
			_, _ = Decode(b, blinded.PublicKey(), client, time.Unix(1502661599, 0))
			return
		}
		// Authenticated plaintext must be bounded and its intro points must
		// have distinct onion/enc keys (Encode enforces this).
		if len(d.IntroPoints) > 20 {
			t.Fatal("too many intro points from authenticated decode")
		}
		// Parse (outer-only) must also succeed on any Decode-success input.
		if _, err := Parse(b); err != nil {
			t.Fatal("Decode accepted input that Parse rejects")
		}
	})
}

func seedValidDescriptor(blinded *hscrypto.BlindedPrivateKey) ([]byte, error) {
	relayKey, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		return nil, err
	}
	encKey, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		return nil, err
	}
	auth := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	addr, err := lspec.FromWire(0, []byte{127, 0, 0, 1, 0x23, 0x29})
	if err != nil {
		return nil, err
	}
	return Encode(EncodeOptions{
		BlindedKey:        blinded,
		SigningKey:        ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32)),
		RevisionCounter:   1<<63 + 42,
		CertificateExpiry: time.Now().Add(48 * time.Hour),
		IntroPoints: []IntroPoint{{
			OnionKey:  relayKey.PublicKey().Bytes(),
			EncKey:    encKey.PublicKey().Bytes(),
			AuthKey:   auth[32:],
			LinkSpecs: []lspec.Lspec{addr, lspec.NewNodeID([20]byte{7})},
		}},
	})
}
