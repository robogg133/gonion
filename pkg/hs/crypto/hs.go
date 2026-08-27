package crypto

import "crypto/sha3"

const (
	LabelCredential    = "credential"
	LabelSubCredential = "subcredential"
)

type (
	Credential    []byte
	SubCredential []byte
)

func GenerateCredential(publicIdentityKey []byte) (Credential, error) {
	h := sha3.New256()
	h.Write([]byte(LabelCredential))
	h.Write(publicIdentityKey)
	return h.Sum(nil), nil
}

func GenerateSubCredential(credential Credential, blindedPk []byte) (SubCredential, error) {
	h := sha3.New256()
	h.Write([]byte(LabelSubCredential))
	h.Write(credential)
	h.Write(blindedPk)
	return h.Sum(nil), nil
}
