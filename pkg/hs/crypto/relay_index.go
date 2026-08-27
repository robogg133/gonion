package crypto

import "crypto/sha3"

const NodeIdx = "node-idx"

type HsRelayIndex []byte

func RelayIndex(nodeIdentity, sharedRandomValue []byte, periodNum, periodLen uint64) HsRelayIndex {
	sha := sha3.New256()
	sha.Write([]byte(NodeIdx))
	sha.Write(nodeIdentity)
	sha.Write(sharedRandomValue)
	writePeriods(sha, periodNum, periodLen)
	return sha.Sum(nil)
}
