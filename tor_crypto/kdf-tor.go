package tor_crypto

import (
	"bytes"
	"crypto/sha1"
)

const (
	SHA1Len = 20
	KeyLen  = 16
)

type CircuitKeys struct {
	KH []byte
	Df []byte
	Db []byte
	Kf []byte
	Kb []byte
}

func DeriveKeysCreateFast(X, Y [20]byte) (*CircuitKeys, error) {

	K0 := append(X[:], Y[:]...)

	var K bytes.Buffer
	for i := byte(0); K.Len() < 92; i++ {
		h := sha1.New()
		h.Write(K0)
		h.Write([]byte{i})
		K.Write(h.Sum(nil))
	}

	stream := K.Bytes()

	keys := &CircuitKeys{
		KH: stream[0:20],
		Df: stream[20:40],
		Db: stream[40:60],
		Kf: stream[60:76],
		Kb: stream[76:92],
	}

	return keys, nil
}
