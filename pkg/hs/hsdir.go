package hs

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// HSDir hash-ring indices, rend-spec §WHERE-HSDESC (verified against
// tor hs_common.c hs_build_hs_index/hs_build_hsdir_index and hs_indexes.py).
//
//	service_index = SHA3-256("store-at-idx" || blinded_pk ||
//	                        INT_8(replica) || INT_8(period_len) || INT_8(period_num))
//	relay_index   = SHA3-256("node-idx" || node_identity ||
//	                        shared_random_value ||
//	                        INT_8(period_num) || INT_8(period_len))
//
// INT_8 fields are big-endian uint64 (tor htonll). Note the service index comes
// replica || period_len || period_num, but the relay index is period_num first.

// ReplicaCount is the consensus default for hsdir_n_replicas.
const ReplicaCount = 2

// ServiceIndex returns the hash-ring position where the descriptor for the
// given blinded key + replica is stored during the given period.
func ServiceIndex(blindedKey []byte, replica, periodLenMin int, periodNum uint64) ([32]byte, error) {
	return hashFrom("store-at-idx", [][]byte{
		blindedKey,
		be64(uint64(replica)),
		be64(uint64(periodLenMin)),
		be64(periodNum),
	})
}

// RelayIndex returns the hash-ring position of an HSD relay with the given
// ed25519 identity, for a shared random value srv during the given period.
func RelayIndex(nodeIdentity, srv []byte, periodLenMin int, periodNum uint64) ([32]byte, error) {
	return hashFrom("node-idx", [][]byte{
		nodeIdentity,
		srv,
		be64(periodNum),
		be64(uint64(periodLenMin)),
	})
}

func hashFrom(prefix string, parts [][]byte) ([32]byte, error) {
	h := sha3.New256()
	h.Write([]byte(prefix))
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
