package crypto

import (
	"bytes"
	"testing"
)

func TestDescKeysRoundTrip(t *testing.T) {
	// A blinded public key is just a 32-byte point for the client.
	bpk := &BlindedPublicKey{
		blindPk: bytes.Repeat([]byte{0x42}, 32),
		pk:      []byte{0x01},
	}

	keys, err := DescKeys(bpk)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.KEnc) != HsDescKeyLen {
		t.Fatalf("KEnc len = %d, want %d", len(keys.KEnc), HsDescKeyLen)
	}
	if len(keys.KMac) != HsDescKeyLen {
		t.Fatalf("KMac len = %d, want %d", len(keys.KMac), HsDescKeyLen)
	}
	if len(keys.KId) != HsDescKeyLen {
		t.Fatalf("KId len = %d, want %d", len(keys.KId), HsDescKeyLen)
	}

	// Determinism: same input → same keys.
	keys2, err := DescKeys(bpk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.KEnc, keys2.KEnc) || !bytes.Equal(keys.KMac, keys2.KMac) || !bytes.Equal(keys.KId, keys2.KId) {
		t.Fatal("DescKeys not deterministic")
	}

	// Different blinded key → different keys.
	other := &BlindedPublicKey{blindPk: bytes.Repeat([]byte{0x99}, 32), pk: []byte{0x02}}
	ok, err := DescKeys(other)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys.KEnc, ok.KEnc) {
		t.Fatal("different blinded keys produced identical KEnc")
	}
}

func TestDescriptorEncryptDecryptRoundTrip(t *testing.T) {
	bpk := &BlindedPublicKey{blindPk: bytes.Repeat([]byte{0x07}, 32), pk: []byte{0x03}}
	keys, err := DescKeys(bpk)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := append([]byte("version 3\nlifetime 180\nintroduction-points auth-key\n"),
		bytes.Repeat([]byte("a"), 200)...)

	blob, err := EncryptDescriptor(keys, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// blob = MAC(32) || ct.
	if len(blob) <= HsDescKeyLen {
		t.Fatalf("blob too short: %d", len(blob))
	}

	got, err := DecryptDescriptor(keys, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt mismatch:\n got %q\nwant %q", got, plaintext)
	}

	// Tampering with ciphertext must fail the MAC.
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 0xff
	if _, err := DecryptDescriptor(keys, bad); err == nil {
		t.Fatal("tampered descriptor accepted")
	}

	// Wrong key must fail.
	wrong := &BlindedPublicKey{blindPk: bytes.Repeat([]byte{0x88}, 32), pk: []byte{0x04}}
	wk, err := DescKeys(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptDescriptor(wk, blob); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
}

func TestE2EKeysLayout(t *testing.T) {
	seed := bytes.Repeat([]byte{0x55}, HsNtorKeySeedLen)
	sub := bytes.Repeat([]byte{0x66}, 32)
	keys, err := E2EKeys(seed, sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Kf) != 16 || len(keys.Kb) != 16 || len(keys.Df) != 20 || len(keys.Db) != 20 {
		t.Fatalf("e2e key sizes wrong: Kf=%d Kb=%d Df=%d Db=%d", len(keys.Kf), len(keys.Kb), len(keys.Df), len(keys.Db))
	}
}
