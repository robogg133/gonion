package crypto_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha3"
	"hash"
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

func TestUnrecognizedDigestRollsBack(t *testing.T) {
	// tor-spec 6.1: a candidate with recognized=0 and a mismatched digest
	// must not advance state. Check against the standard hash, not our writer.
	for _, hs := range []bool{false, true} {
		var rv *crypto.RunningValues
		var reference hash.Hash
		var err error
		seed := bytes.Repeat([]byte{0x42}, 20)
		if hs {
			seed = bytes.Repeat([]byte{0x42}, 32)
			rv, err = crypto.NewHSRunningValues(bytes.Repeat([]byte{1}, 32), seed)
			reference = sha3.New256()
		} else {
			rv, err = crypto.NewRunningValues(bytes.Repeat([]byte{1}, 16), seed)
			reference = sha1.New()
		}
		if err != nil {
			t.Fatal(err)
		}
		reference.Write(seed)
		before := bytes.Clone(rv.Sum())
		plain := make([]byte, 509)
		plain[0], plain[4], plain[10], plain[11] = 2, 1, 1, 42
		reference.Write(plain)
		want := reference.Sum(nil)
		wrong := bytes.Clone(want[:4])
		wrong[0] ^= 1
		if _, ok, err := rv.CheckDigest(plain, wrong); err != nil || ok {
			t.Fatalf("wrong digest: %v", err)
		}
		if !bytes.Equal(rv.Sum(), before) {
			t.Fatal("unrecognized cell changed digest state")
		}
		got, ok, err := rv.CheckDigest(plain, want[:4])
		if err != nil || !ok || !bytes.Equal(got, want) || !bytes.Equal(rv.Sum(), want) {
			t.Fatalf("valid digest after rollback: %v", err)
		}
	}
}

func TestRunningValues_InvalidKey(t *testing.T) {
	_, err := crypto.NewRunningValues([]byte{1, 2, 3}, bytes.Repeat([]byte{0}, 20))
	if err == nil {
		t.Fatal("expected error for bad AES key size")
	}
}
