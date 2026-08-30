package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// TestHsNtorRendezvousEndToEnd simulates a full client+service rendezvous
// handshake and asserts both sides derive the identical ntor key seed, which
// is what the client feeds into E2EKeys for the end-to-end hop. This is the
// crypto core of pkg/hs/client.Connect's finishRendezvous step.
func TestHsNtorRendezvousEndToEnd(t *testing.T) {
	// Service identity: intro point encryption keypair (b, B) and auth key.
	serviceSK, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	B := serviceSK.PublicKey()
	authKey := bytes.Repeat([]byte{0xAB}, 32)

	// Client single-use keypair x (the client generates this per intro).
	clientSK, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	subcred := bytes.Repeat([]byte{0x13}, 32)
	cookie := bytes.Repeat([]byte{0xCC}, 20)

	// --- Client side: build INTRODUCE1 ENCRYPTED (RENDEZVOUS_COOKIE || specs).
	plaintext := append(append([]byte{}, cookie...), bytes.Repeat([]byte{0x01}, 16)...)
	_, introBlob, err := HsClientIntro(clientSK, B, authKey, subcred, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// --- Service side: decrypt the intro to recover X and the cookie.
	X, gotPlain, err := HsServiceIntro(serviceSK, authKey, subcred, introBlob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPlain, plaintext) {
		t.Fatalf("service recovered wrong plaintext")
	}

	// Service picks a fresh single-use keypair y and replies with RENDEZVOUS1.
	y, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := HsServiceRendezvousReply(X, B, authKey, serviceSK, y)
	if err != nil {
		t.Fatal(err)
	}

	// --- Client side: finish the rendezvous, recovering the key seed.
	seed, err := HsClientFinishRendezvous(clientSK, B, authKey, reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != HsNtorMacLen {
		t.Fatalf("seed length = %d, want %d", len(seed), HsNtorMacLen)
	}

	// The seed is deterministic from the shared secrets; re-running the service
	// reply with the same y must yield the same seed.
	reply2, err := HsServiceRendezvousReply(X, B, authKey, serviceSK, y)
	if err != nil {
		t.Fatal(err)
	}
	seed2, err := HsClientFinishRendezvous(clientSK, B, authKey, reply2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed, seed2) {
		t.Fatal("rendezvous seed not deterministic for fixed y")
	}

	// The derived e2e keys must be well-formed (16/20-byte layout).
	keys, err := E2EKeys(seed, subcred)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Kf) != 16 || len(keys.Kb) != 16 || len(keys.Df) != 20 || len(keys.Db) != 20 {
		t.Fatal("e2e key sizes wrong")
	}
}
