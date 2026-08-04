package hs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
)

// Blinding must be consistent between the private and public derivation: the
// public key derived from the blinded *secret* must equal BlindedPublicKey.
func TestBlindingPublicPrivateConsistency(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	masterPub := ed25519.PublicKey(ed25519.NewKeyFromSeed(seed)[pub25519Len:])
	const pNum = 16903
	const pLen = 1440

	blinded, err := BlindedPublicKey(masterPub, nil, pNum, pLen)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := BlindSecretKey(seed, nil, pNum, pLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != expandedSecretKeyLen {
		t.Fatalf("secret len %d, want %d", len(secret), expandedSecretKeyLen)
	}
	// The blinded public = blinded scalar * B, no extra clamp; the scalar is
	// already reduced mod L so canonical decoding is valid.
	s, perr := new(edwards25519.Scalar).SetCanonicalBytes(secret[:32])
	if perr != nil {
		t.Fatal(perr)
	}
	derived := new(edwards25519.Point).ScalarBaseMult(s).Bytes()
	if !bytes.Equal(derived, blinded) {
		t.Fatalf("blinded pubkeys differ:\n blindpub=%x\n  derived=%x", blinded, derived)
	}
}

// Distinct periods must produce distinct blinded keys and subcredentials.
func TestBlindingChangesPerPeriod(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	masterPub := ed25519.PublicKey(ed25519.NewKeyFromSeed(seed)[32:])

	a, _ := BlindedPublicKey(masterPub, nil, 1000, 1440)
	b, _ := BlindedPublicKey(masterPub, nil, 1001, 1440)
	if bytes.Equal(a, b) {
		t.Fatal("blinded keys should differ across periods")
	}

	subA := Subcredential(masterPub, a)
	subB := Subcredential(masterPub, b)
	if bytes.Equal(subA[:], subB[:]) {
		t.Fatal("subcredentials should differ across periods")
	}
	again := Subcredential(masterPub, a)
	if !bytes.Equal(subA[:], again[:]) {
		t.Fatal("subcredential not deterministic")
	}
}

func TestCredentialDeterministic(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	c1 := Credential(pub)
	c2 := Credential(pub)
	if !bytes.Equal(c1[:], c2[:]) {
		t.Fatal("credential must be deterministic")
	}
}
