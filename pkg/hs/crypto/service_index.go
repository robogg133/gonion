package crypto

import (
	"crypto/sha3"
	"encoding/binary"
)

const StoreAtIdx = "store-at-idx"

type HsServiceIndex []byte

func (bk *BlindedPublicKey) ServiceIndex(replicaN uint64) HsServiceIndex {
	sha := sha3.New256()

	sha.Write([]byte(StoreAtIdx))
	sha.Write(bk.blindPk)
	binary.Write(sha, binary.BigEndian, replicaN)
	binary.Write(sha, binary.BigEndian, bk.periodLenght)
	binary.Write(sha, binary.BigEndian, bk.periodNumber)
	return sha.Sum(nil)
}
