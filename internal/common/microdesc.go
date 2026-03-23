package common

import (
	"encoding/hex"
	"strings"
)

type Microdesc struct {
	OnionKey     []byte
	NTorOnionKey []byte
	IdEd25519    []byte
	Family       [][]byte
}

func parseMicrodescBlock() {

}

func parseFamily(s string) (family [][]byte, err error) {
	split := strings.SplitSeq(s, " ")

	for v := range split {
		v = strings.TrimPrefix(v, "$")
		b, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}

		family = append(family, b)
	}

	return family, nil
}
