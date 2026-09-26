package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/binary"
	"testing"
)

func TestEstablishIntroAuthentication(t *testing.T) {
	// RFC 8032 test 1 identity; rend-spec-v3 EST_INTRO layout and MAC formula
	// checked independently of EstablishIntro/hsMac, as in C Tor test_hs_cell.
	key := ed25519.NewKeyFromSeed(vectorHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	kh := bytes.Repeat([]byte{0x42}, 20)
	cell, err := EstablishIntro(key, kh)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := cell.Encode(&encoded); err != nil {
		t.Fatal(err)
	}
	wire := encoded.Bytes()
	prefix := append([]byte{2, 0, 32}, key[32:]...)
	prefix = append(prefix, 0)
	if len(wire) != 134 || !bytes.Equal(wire[:36], prefix) || binary.BigEndian.Uint16(wire[68:70]) != 64 {
		t.Fatalf("wrong ESTABLISH_INTRO layout: %x", wire)
	}
	macInput := binary.BigEndian.AppendUint64(nil, uint64(len(kh)))
	macInput = append(macInput, kh...)
	macInput = append(macInput, prefix...)
	mac := sha3.Sum256(macInput)
	if !bytes.Equal(wire[36:68], mac[:]) {
		t.Fatal("circuit-binding MAC mismatch")
	}
	message := append([]byte("Tor establish-intro cell v1"), wire[:68]...)
	if !ed25519.Verify(ed25519.PublicKey(key[32:]), message, wire[70:]) {
		t.Fatal("invalid introduction signature")
	}
	otherKH := bytes.Clone(kh)
	otherKH[0] ^= 1
	other, err := EstablishIntro(key, otherKH)
	if err != nil || bytes.Equal(other.MAC, cell.MAC) || bytes.Equal(other.Sig, cell.Sig) {
		t.Fatal("nonce did not bind authentication and signature")
	}
	if _, err := EstablishIntro(key, kh[:19]); err == nil {
		t.Fatal("short nonce accepted")
	}
	key[63] ^= 1
	if _, err := EstablishIntro(key, kh); err == nil {
		t.Fatal("inconsistent private key accepted")
	}
}
