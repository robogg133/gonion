package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha3"
	"crypto/subtle"
	"encoding"
	"fmt"
	"hash"
	"sync"
)

type RunningValues struct {
	digest    hash.Hash
	aes128Ctr cipher.Stream

	mu sync.RWMutex
}

func NewRunningValues(EncryptionKey []byte, DigestStarter []byte) (*RunningValues, error) {
	return newRunningValues(EncryptionKey, DigestStarter, sha1.New())
}

// NewHSRunningValues implements rend-spec-v3 4.2.1, not ordinary ntor crypto.
func NewHSRunningValues(key, seed []byte) (*RunningValues, error) {
	if len(key) != 32 || len(seed) != 32 {
		return nil, fmt.Errorf("HS hop requires 32-byte AES key and SHA3 digest seed")
	}
	return newRunningValues(key, seed, sha3.New256())
}

func newRunningValues(EncryptionKey, DigestStarter []byte, digest hash.Hash) (*RunningValues, error) {
	rv := &RunningValues{digest: digest}
	// Starting digest
	_, err := rv.digest.Write(DigestStarter)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(EncryptionKey)
	if err != nil {
		return nil, err
	}

	tmp := make([]byte, 16)
	rv.aes128Ctr = cipher.NewCTR(block, tmp)

	return rv, nil
}

func (rv *RunningValues) Sum() []byte {
	rv.mu.RLock()
	defer rv.mu.RUnlock()

	return rv.digest.Sum(nil)
}

// Write writes data to the digest
func (rv *RunningValues) Write(b []byte) error {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	_, err := rv.digest.Write(b)
	return err
}

// CheckDigest commits a digest update only when the cell is recognized. A
// coincidental zero recognized field must not corrupt this hop's running hash.
func (rv *RunningValues) CheckDigest(data, expected []byte) ([]byte, bool, error) {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	state, err := rv.digest.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, false, err
	}
	if _, err := rv.digest.Write(data); err != nil {
		return nil, false, err
	}
	sum := rv.digest.Sum(nil)
	if len(expected) == 4 && subtle.ConstantTimeCompare(sum[:4], expected) == 1 {
		return sum, true, nil
	}
	if err := rv.digest.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src must overlap entirely or not at all.
//
// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
//
// Multiple calls to XORKeyStream behave as if the concatenation of
// the src buffers was passed in a single run. That is, Stream
// maintains state and does not reset at each XORKeyStream call.
func (rv *RunningValues) XORKeyStream(dst, src []byte) {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	rv.aes128Ctr.XORKeyStream(dst, src)
}
