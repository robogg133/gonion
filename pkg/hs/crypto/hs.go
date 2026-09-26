package crypto

import (
	"crypto/sha3"
	"errors"
)

const (
	LabelCredential    = "credential"
	LabelSubCredential = "subcredential"
)

type (
	Credential    []byte
	SubCredential []byte
)

func GenerateCredential(publicIdentityKey []byte) (Credential, error) {
	if err := ValidateEd25519PublicKey(publicIdentityKey); err != nil {
		return nil, err
	}
	h := sha3.New256()
	h.Write([]byte(LabelCredential))
	h.Write(publicIdentityKey)
	return h.Sum(nil), nil
}

func GenerateSubCredential(credential Credential, blindedPk []byte) (SubCredential, error) {
	if len(credential) != 32 {
		return nil, errors.New("hs/crypto: invalid credential length")
	}
	if err := ValidateEd25519PublicKey(blindedPk); err != nil {
		return nil, err
	}
	h := sha3.New256()
	h.Write([]byte(LabelSubCredential))
	h.Write(credential)
	h.Write(blindedPk)
	return h.Sum(nil), nil
}
