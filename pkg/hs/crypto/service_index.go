package crypto

import (
	"crypto/sha3"
	"encoding/binary"
)

const StoreAtIdx = "store-at-idx"

type HsServiceIndex []byte

// ServiceIndex hashes replica, period length (minutes), then period number,
// in that order (rend-spec-v3 WHERE-HSDESC).
func (bk *BlindedPublicKey) ServiceIndex(replicaN uint64) HsServiceIndex {
	if bk == nil || len(bk.blindPk) != 32 || bk.periodLenght == 0 || replicaN < 1 || replicaN > 16 {
		return nil
	}
	sha := sha3.New256()

	sha.Write([]byte(StoreAtIdx))
	sha.Write(bk.blindPk)
	binary.Write(sha, binary.BigEndian, replicaN)
	binary.Write(sha, binary.BigEndian, bk.periodLenght)
	binary.Write(sha, binary.BigEndian, bk.periodNumber)
	return sha.Sum(nil)
}
