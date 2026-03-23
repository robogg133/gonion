package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"hash"
	"sync"
)

type RunningValues struct {
	digest    hash.Hash
	aes128Ctr cipher.Stream

	lastDataCellSum [20]byte

	mu sync.RWMutex
}

func NewRunningValues(EncryptionKey []byte, DigestStarter []byte) (*RunningValues, error) {
	rv := &RunningValues{
		digest: sha1.New(),
	}
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

func (rv *RunningValues) SetLastSumDataCell(sum [20]byte) {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	rv.lastDataCellSum = sum
}
func (rv *RunningValues) GetLastSumDataCell() [20]byte {
	rv.mu.RLock()
	defer rv.mu.RUnlock()

	return rv.lastDataCellSum
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

func (rv *RunningValues) XORKeyStream(dst, src []byte) {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	rv.aes128Ctr.XORKeyStream(dst, src)
}
