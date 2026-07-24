package crypto_test

import (
	"bytes"
	"testing"

	"github.com/robogg133/gonion/pkg/crypto"
)

func TestRunningValues_XORRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 16)
	dig := bytes.Repeat([]byte{0xcd}, 20)

	enc, err := crypto.NewRunningValues(key, dig)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := crypto.NewRunningValues(key, dig)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("hello onion crypto!!")
	ct := make([]byte, len(plain))
	enc.XORKeyStream(ct, plain)

	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	out := make([]byte, len(ct))
	dec.XORKeyStream(out, ct)
	if !bytes.Equal(out, plain) {
		t.Fatalf("roundtrip failed: %q", out)
	}
}

func TestRunningValues_DigestAdvances(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	dig := bytes.Repeat([]byte{2}, 20)
	rv, err := crypto.NewRunningValues(key, dig)
	if err != nil {
		t.Fatal(err)
	}
	s0 := append([]byte(nil), rv.Sum()...)
	if err := rv.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	s1 := rv.Sum()
	if bytes.Equal(s0, s1) {
		t.Fatal("digest should change after Write")
	}
}

func TestRunningValues_InvalidKey(t *testing.T) {
	_, err := crypto.NewRunningValues([]byte{1, 2, 3}, bytes.Repeat([]byte{0}, 20))
	if err == nil {
		t.Fatal("expected error for bad AES key size")
	}
}
