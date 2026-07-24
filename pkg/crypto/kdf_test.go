package crypto_test

import (
	"bytes"
	"testing"

	"github.com/robogg133/gonion/pkg/crypto"
)

func TestDeriveKeysCreateFast_Lengths(t *testing.T) {
	var x, y [20]byte
	for i := range x {
		x[i] = byte(i)
		y[i] = byte(255 - i)
	}
	keys, err := crypto.DeriveKeysCreateFast(x, y)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.KH) != 20 || len(keys.Df) != 20 || len(keys.Db) != 20 {
		t.Fatalf("digest lens KH=%d Df=%d Db=%d", len(keys.KH), len(keys.Df), len(keys.Db))
	}
	if len(keys.Kf) != 16 || len(keys.Kb) != 16 {
		t.Fatalf("key lens Kf=%d Kb=%d", len(keys.Kf), len(keys.Kb))
	}
}

func TestDeriveKeysCreateFast_Deterministic(t *testing.T) {
	var x, y [20]byte
	copy(x[:], bytes.Repeat([]byte{0x11}, 20))
	copy(y[:], bytes.Repeat([]byte{0x22}, 20))

	a, err := crypto.DeriveKeysCreateFast(x, y)
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.DeriveKeysCreateFast(x, y)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.KH, b.KH) || !bytes.Equal(a.Kf, b.Kf) || !bytes.Equal(a.Kb, b.Kb) {
		t.Fatal("same inputs must yield same keys")
	}
}

func TestDeriveKeysCreateFast_DifferentMaterial(t *testing.T) {
	var x1, x2, y [20]byte
	x1[0] = 1
	x2[0] = 2
	a, _ := crypto.DeriveKeysCreateFast(x1, y)
	b, _ := crypto.DeriveKeysCreateFast(x2, y)
	if bytes.Equal(a.KH, b.KH) {
		t.Fatal("different X should change KH")
	}
}
