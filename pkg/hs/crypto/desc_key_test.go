package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDescriptorEncryptDecryptRoundTrip(t *testing.T) {
	// Blinded key and subcredential from Tor test_hs_common.c,
	// test_blinding_basics (period 1234, 1440 minutes).
	blinded := hexBytes(t, "3a50bf210e8f9ee955ae0014f7a6917fb65ebf098a86305abb508d1a7291b6d5")
	sub := hexBytes(t, "635d55907816e8d76398a675a50b1c2f3e36b42a5ca77ba3a0441285161ae07d")
	plaintext := []byte("create2-formats 2\n")
	for _, layer := range []DescriptorLayer{EncryptedLayer, SuperencryptedLayer} {
		blob, err := EncryptDescriptor(blinded, sub, 42, layer, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if len(blob) != len(plaintext)+48 {
			t.Fatal("incorrect SALT/ciphertext/MAC layout")
		}
		got, err := DecryptDescriptor(blinded, sub, 42, layer, blob)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip: %q %v", got, err)
		}
		again, err := EncryptDescriptor(blinded, sub, 42, layer, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(blob[:16], again[:16]) {
			t.Fatal("salt reused")
		}
		for _, offset := range []int{0, 16, len(blob) - 1} {
			bad := bytes.Clone(blob)
			bad[offset] ^= 1
			if _, err := DecryptDescriptor(blinded, sub, 42, layer, bad); err == nil {
				t.Fatal("tampering accepted")
			}
		}
		if _, err := DecryptDescriptor(blinded, sub, 43, layer, blob); err == nil {
			t.Fatal("wrong revision accepted")
		}
		other := EncryptedLayer
		if layer == EncryptedLayer {
			other = SuperencryptedLayer
		}
		if _, err := DecryptDescriptor(blinded, sub, 42, other, blob); err == nil {
			t.Fatal("wrong layer accepted")
		}
		if _, err := DecryptDescriptor(blinded, bytes.Repeat([]byte{3}, 32), 42, layer, blob); err == nil {
			t.Fatal("wrong subcredential accepted")
		}
		for n := 0; n <= 48; n++ {
			if _, err := DecryptDescriptor(blinded, sub, 42, layer, blob[:n]); err == nil {
				t.Fatal("short blob accepted")
			}
		}
	}
}

func TestTorBlindingVector(t *testing.T) {
	// Exact expanded private-key vector from Tor test_hs_common.c.
	pk := hexBytes(t, "833990b085c1a688c1d4c8b1f6b56afaf5a2eca674449e1d704f83765ccb7bc6")
	expanded := hexBytes(t, "d8c7ff0e31295b66540d789af3e3df992038a9592eea01d8b7cba06d6e66d1594d6167696320576f7264733a20737065697373636f62616c742062697669756d")
	k, err := blindExpanded(pk, expanded, 1234, 1440)
	if err != nil {
		t.Fatal(err)
	}
	want := hexBytes(t, "a958dc83ac885f6814c67035de817a2c604d5d2f715282079448f789b656350b4540fe1f80aa3f7e91306b7bf7a8e367293352b14a29fdcc8c19f3558075524b")
	if !bytes.Equal(k.scalar.Bytes(), want[:32]) || !bytes.Equal(k.prefix[:], want[32:]) {
		t.Fatalf("blinded expanded secret mismatch: %x%x", k.scalar.Bytes(), k.prefix)
	}
	if !bytes.Equal(k.PublicKey().Bytes(), hexBytes(t, "3a50bf210e8f9ee955ae0014f7a6917fb65ebf098a86305abb508d1a7291b6d5")) {
		t.Fatal("blinded public vector mismatch")
	}
	cred, err := GenerateCredential(pk)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := GenerateSubCredential(cred, k.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sub, hexBytes(t, "635d55907816e8d76398a675a50b1c2f3e36b42a5ca77ba3a0441285161ae07d")) {
		t.Fatal("subcredential vector mismatch")
	}
	sig, err := k.Sign([]byte("Tor certificate signing check"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(k.PublicKey().Bytes(), []byte("Tor certificate signing check"), sig) {
		t.Fatal("blinded Ed25519 signature invalid")
	}
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	standard, err := BlindPrivateKey(identity, 1234, 1440)
	if err != nil {
		t.Fatal(err)
	}
	public := BlindPk(ed25519.PublicKey(identity[32:]), 1234, 1440)
	if !bytes.Equal(standard.PublicKey().Bytes(), public.Bytes()) {
		t.Fatal("standard private/public blinding mismatch")
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 32), append([]byte{1}, make([]byte, 31)...)} {
		if _, err := BlindPublicKey(bad, 1, 1440); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}

func TestE2EKeysLayout(t *testing.T) {
	seed := bytes.Repeat([]byte{0x55}, HsNtorKeySeedLen)
	sub := bytes.Repeat([]byte{0x66}, 32)
	keys, err := E2EKeys(seed, sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Kf) != 32 || len(keys.Kb) != 32 || len(keys.Df) != 32 || len(keys.Db) != 32 {
		t.Fatalf("e2e key sizes wrong: Kf=%d Kb=%d Df=%d Db=%d", len(keys.Kf), len(keys.Kb), len(keys.Df), len(keys.Db))
	}
}
