package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

// EstablishIntro authenticates ESTABLISH_INTRO to this circuit's KH nonce
// (tor-spec 5.2.2; rend-spec-v3 EST_INTRO). It does not send the cell.
func EstablishIntro(auth ed25519.PrivateKey, kh []byte) (*relay.EstIntroCell, error) {
	if len(auth) != ed25519.PrivateKeySize || len(kh) != 20 {
		return nil, errors.New("hs: invalid introduction key or circuit nonce")
	}
	canonical := ed25519.NewKeyFromSeed(auth[:32])
	defer clear(canonical)
	if !bytes.Equal(auth, canonical) {
		return nil, errors.New("hs: inconsistent introduction private key")
	}
	prefix := append([]byte{2, 0, 32}, auth[32:]...)
	prefix = append(prefix, 0) // no extensions
	mac := hsMac(kh, prefix)
	signed := append([]byte("Tor establish-intro cell v1"), prefix...)
	signed = append(signed, mac...)
	return &relay.EstIntroCell{AuthKey: bytes.Clone(auth[32:]), MAC: mac, Sig: ed25519.Sign(auth, signed)}, nil
}
