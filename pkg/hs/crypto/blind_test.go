package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"bytes"
	"testing"
)

func TestBlindPkSanity(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	b1 := BlindPk(pub, 1000, 86400)
	if len(b1.blindPk) != 32 {
		t.Fatalf("blind pk len = %d", len(b1.blindPk))
	}
	if bytes.Equal(b1.blindPk, pub) {
		t.Fatal("blinded key equals original")
	}

	b2 := BlindPk(pub, 1000, 86400)
	if !bytes.Equal(b1.blindPk, b2.blindPk) {
		t.Fatal("not deterministic")
	}

	b3 := BlindPk(pub, 1001, 86400)
	if bytes.Equal(b1.blindPk, b3.blindPk) {
		t.Fatal("different period produced same blinded key")
	}
}