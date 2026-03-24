package common

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

type Microdesc struct {
	OnionKey     []byte
	NTorOnionKey []byte
	IdEd25519    []byte
	Family       [][]byte
	Familys      []*FamilyIDs
}

type FamilyIDs struct {
	Kind  string
	Value []byte
}

func parseMicrodescBlock() {

}

func parseFamilys(s string) (ids []*FamilyIDs, err error) {
	split := strings.SplitSeq(s, " ")

	for str := range split {

		id := strings.SplitN(str, ":", 2)

		a := &FamilyIDs{
			Kind: id[0],
		}
		var err error
		a.Value, err = base64.RawStdEncoding.DecodeString(id[1])
		if err != nil {
			return nil, err
		}

		ids = append(ids, a)
	}

	return nil, nil
}

func parseFamily(s string) (family [][]byte, err error) {
	split := strings.SplitSeq(s, " ")

	for str := range split {
		str = strings.TrimPrefix(str, "$")
		b, err := hex.DecodeString(str)
		if err != nil {
			return nil, err
		}

		family = append(family, b)
	}

	return family, nil
}
