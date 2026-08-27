package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestHsNtorClientServiceRoundTrip(t *testing.T) {
	clientSK, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Intro point encryption keypair ("b", "B").
	serviceSK, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authKey := bytes.Repeat([]byte{0xAB}, 32)
	subcred := bytes.Repeat([]byte{0x13}, 32)
	plaintext := append([]byte{0x01, 0x02, 0x03}, bytes.Repeat([]byte{0x00}, 200)...)

	// Client builds the INTRODUCE1 ENCRYPTED blob.
	_, blob, err := HsClientIntro(clientSK, serviceSK.PublicKey(), authKey, subcred, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Service decrypts it.
	X, gotPlain, err := HsServiceIntro(serviceSK, authKey, subcred, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPlain, plaintext) {
		t.Fatalf("plaintext mismatch")
	}

	// Service replies (RENDEZVOUS1 handshake info).
	y, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := HsServiceRendezvousReply(X, serviceSK.PublicKey(), authKey, serviceSK, y)
	if err != nil {
		t.Fatal(err)
	}

	// Client validates the reply and derives the same ntor key seed.
	seed, err := HsClientFinishRendezvous(clientSK, serviceSK.PublicKey(), authKey, reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != HsNtorMacLen {
		t.Fatalf("seed len=%d", len(seed))
	}
}

func TestHsNtorIntroTamper(t *testing.T) {
	clientSK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	serviceSK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, blob, _ := HsClientIntro(clientSK, serviceSK.PublicKey(), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), []byte("data"))

	blob[len(blob)-1] ^= 0xff
	if _, _, err := HsServiceIntro(serviceSK, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), blob); err == nil {
		t.Fatal("tampered intro accepted")
	}
}
